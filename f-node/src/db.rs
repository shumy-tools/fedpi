use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::sync::atomic::{AtomicBool, Ordering};
use std::any::Any;
use std::cell::RefCell;

use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;

use sled::{Db, IVec, Batch};
use sha2::{Sha512, Digest};
use log::info;

use core_fpi::keys::*;
use core_fpi::messages::*;

pub const STATE: &str = "$state";
pub const MASTER: &str = "master";
pub const ENCRYPT: &str = "encrypt";

//--------------------------------------------------------------------
// Rules to derive keys. Always use a prefix to avoid security issues, such as data override from different protocols!
//--------------------------------------------------------------------
pub fn sid(sid: &str) -> String { format!("sid-{}", sid) }                              // subject-id
pub fn aid(sid: &str) -> String { format!("aid-{}", sid) }                              // authorizations-id
pub fn pid(kid: &str) -> String { format!("pid-{}", kid) }                              // master-key-pair-id

pub fn cid(sid: &str, sig: &str) -> String { format!("cid-{}-{}", sid, sig) }           // consent-id
pub fn vid(kid: &str, sig: &str) -> String { format!("vid-{}-{}", kid, sig) }           // master-key-vote-id
pub fn eid(kid: &str, sig: &str) -> String { format!("eid-{}-{}", kid, sig) }           // master-key-id (evidence)

//--------------------------------------------------------------------
// AppDB
//--------------------------------------------------------------------
pub struct AppDB {
    store: Arc<Db>,
    cache: Arc<Mutex<MemCache>>,
    tx: Mutex<DbTx>,
}

impl AppDB {
    pub fn new(home: &str) -> Self {
        let store_file = format!("{}/app/store.db", home);
        let store = Arc::new(Db::open(store_file).unwrap());

        // initialize app-state cache
        let state: Option<AppState> = get(store.clone(), STATE);
        let state = state.unwrap_or_else(|| AppState { height: 0, hash: Vec::<u8>::new() });
        info!("STATE - (height = {:?}, hash = {:?})", state.height, bs58::encode(&state.hash).into_string());

        let cache = MemCache::new();
        cache.set(STATE, state);
        let cache = Arc::new(Mutex::new(cache));

        let tx = Mutex::new(DbTx::new(store.clone(), cache.clone()));
        Self { store, cache, tx }
    }

    pub fn state(&self) -> AppState {
        let guard = self.cache.lock().unwrap();
        guard.get(STATE).unwrap()
    }

    pub fn key(&self, kid: &str) -> Option<MasterKeyPair> {
        let kid = pid(kid);

        let guard = self.cache.lock().unwrap();
        let cached = guard.get(&kid);
        if cached.is_some() {
            return cached
        }

        //TODO: decrypt key from storage
        let mkey: Option<MasterKeyPair> = self.get(&kid);
        match mkey {
            None => None,
            Some(obj) => {
                guard.set(&kid, obj.clone());
                Some(obj)
            }
        }
    }

    pub fn contains(&self, id: &str) -> bool {
        contains(self.store.clone(), id)
    }

    pub fn get<T: DeserializeOwned + Clone + Send + Sync + 'static>(&self, id: &str) -> Option<T> {
        get(self.store.clone(), id)
    }

    pub fn start(&self) {
        let tx = self.tx.lock().unwrap();
        if tx.pending() {
            panic!("Unexpected pending transaction at start!");
        }
    }

    pub fn tx(&self) -> MutexGuard<DbTx> {
        self.tx.lock().unwrap()
    }

    pub fn commit(&self, height: i64) -> AppState {
        let tx = self.tx.lock().unwrap();
        let new_state = tx.commit(height);
        
        let guard = self.cache.lock().unwrap();
        guard.set(STATE, new_state.clone());

        new_state
    }
}

//--------------------------------------------------------------------
// DbTx
//--------------------------------------------------------------------
pub struct DbTx {
    store: Arc<Db>,
    cache: Arc<Mutex<MemCache>>,

    pending: AtomicBool,
    view: Mutex<MemCache>,
    local: Mutex<MemCache>,
}

impl DbTx {
    fn new(store: Arc<Db>, cache: Arc<Mutex<MemCache>>) -> Self {
        Self { store, cache, pending: AtomicBool::new(false), view: Mutex::new(MemCache::new()), local: Mutex::new(MemCache::new()) }
    }

    pub fn pending(&self) -> bool {
        self.pending.load(Ordering::Relaxed)
    }

    pub fn contains(&self, id: &str) -> bool {
        let guard = self.view.lock().unwrap();

        if !guard.contains(id) {
            return contains(self.store.clone(), id)
        }

        true
    }

    pub fn get<T: Serialize + DeserializeOwned + Clone + Send + Sync + 'static>(&self, id: &str) -> Option<T> {
        let guard = self.view.lock().unwrap();

        let cached = guard.get(id);
        if cached.is_some() {
            return cached
        }

        let value: Option<T> = get(self.store.clone(), id);
        if let Some(value) = &value {
            //may poison the mutex if the encode fails! The transaction should fail.
            guard.set(id, value.clone());
        }

        value
    }

    pub fn set<T: Serialize + Clone + Send + Sync + 'static>(&self, id: &str, value: T) {
        if id.starts_with('$') {
            panic!("Trying to set a reserved key!");
        }
        
        self.pending.store(true, Ordering::Relaxed);
        
        let guard = self.view.lock().unwrap();
        guard.set(id, value);
    }

    // doesn't include the value in the app-state
    pub fn set_local<T: Serialize + Clone + Send + Sync + 'static>(&self, id: &str, value: T)  {
        if id.starts_with('$') {
            panic!("Trying to set a reserved key!");
        }

        self.pending.store(true, Ordering::Relaxed);

        //TODO: encrypt storage?
        let guard = self.local.lock().unwrap();
        guard.set(id, value);
    }

    fn commit(&self, height: i64) -> AppState {
        //TODO: verify if state.height + 1 == height ?

        let store = self.store.clone();
        let state: AppState = get(self.store.clone(), STATE).unwrap();

        // returns and clears all MemCache data
        let global_data = self.view.lock().unwrap().data();
        let local_data = self.local.lock().unwrap().data();

        let mut batch = Batch::default();
        let mut hasher = Sha512::new();
        hasher.input(state.hash);

        // update global tx data
        for (key, value) in global_data.into_iter() {
            hasher.input(&value);
            batch.insert(&key as &str, value);
        }

        // update local tx data
        for (key, value) in local_data.into_iter() {
            batch.insert(&key as &str, value);
        }

        // update app-state
        let new_state = AppState { height, hash: hasher.result().to_vec() };
        let state_data = encode(&new_state).expect("Unable to encode structure!");;
        batch.insert(STATE, state_data);

        // commit batch
        store.apply_batch(batch).unwrap();
        store.flush().map_err(|e| format!("Unable to flush: {}", e)).unwrap();

        self.pending.store(false, Ordering::Relaxed);
        new_state
    }
}

//--------------------------------------------------------------------
// MemCache
//--------------------------------------------------------------------
type SafeAny = Any + Send + Sync;

struct MemCache {
    data_cache: RefCell<HashMap<String, Vec<u8>>>,
    obj_cache: RefCell<HashMap<String, Box<SafeAny>>>,
}

impl MemCache {
    fn new() -> Self {
        Self { data_cache: RefCell::new(HashMap::new()), obj_cache: RefCell::new(HashMap::new()) }
    }

    fn contains(&self, id: &str) -> bool {
        let map = self.obj_cache.borrow();
        map.contains_key(id)
    }

    fn get<T: Clone + Send + Sync + 'static>(&self, id: &str) -> Option<T> {
        let map = self.obj_cache.borrow();
        let value = map.get(id);

        match value {
            None => None,
            Some(bv) => {
                let casted = bv.downcast_ref::<T>();
                if casted.is_none() {
                    panic!("Unable to downcast to expected type!");
                }

                casted.cloned()
            }
        }
    }

    fn set<T: Serialize + Clone + Send + Sync + 'static>(&self, id: &str, value: T) {
        let data = encode(&value).expect("Unable to encode structure!");
        let mut map = self.data_cache.borrow_mut();
        map.insert(id.into(), data);

        let mut map = self.obj_cache.borrow_mut();
        map.insert(id.into(), Box::new(value));
    }

    fn data(&self) -> HashMap<String, Vec<u8>> {
        let mut map = self.obj_cache.borrow_mut();
        map.clear();

        self.data_cache.replace(HashMap::new())
    }
}

//--------------------------------------------------------------------
// Generic database functions and structures
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppState {
    pub height: i64,
    pub hash: Vec<u8>
}

fn contains(db: Arc<Db>, id: &str) -> bool {
    db.contains_key(id).map_err(|e| format!("Unable to verify if key exists: {}", e)).unwrap()
}

fn get<T: DeserializeOwned>(db: Arc<Db>, id: &str) -> Option<T> {
    let res: Option<IVec> = db.get(id)
        .map_err(|e| format!("Unable to get value from storage: {}", e)).unwrap();
    
    match res {
        None => None,
        Some(data) => {
            let obj: T = decode(&data).map_err(|e| format!("Unable to decode value from storage: {}", e)).unwrap();
            Some(obj)
        }
    }
}