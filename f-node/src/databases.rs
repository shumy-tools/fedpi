use std::collections::HashMap;
use std::rc::Rc;
use std::any::Any;
use std::cell::RefCell;
use std::sync::Mutex;

use serde::{Serialize, Deserialize};
use serde::de::DeserializeOwned;

use sled::{Db, IVec, TransactionError, TransactionalTree};
use sha2::{Sha512, Digest};
use log::{error, info};

use core_fpi::Result;
use core_fpi::ids::*;
use core_fpi::keys::*;
use core_fpi::authorizations::*;
use core_fpi::messages::{encode, decode};

//--------------------------------------------------------------------
// Reserved keys
//--------------------------------------------------------------------
pub const HASH: &str = "$hash";
pub const STATE: &str = "$state";
pub const MASTER: &str = "master";

//--------------------------------------------------------------------
// Rules to derive keys. Always use a prefix to avoid security issues, such as data override from different protocols!
//--------------------------------------------------------------------
fn sid(sid: &str) -> String { format!("sid-{}", sid) }                              // subject-id
fn aid(sid: &str) -> String { format!("aid-{}", sid) }                              // authorizations-id
fn pid(kid: &str) -> String { format!("pid-{}", kid) }                              // master-key-pair-id

fn cid(sid: &str, sig: &str) -> String { format!("cid-{}-{}", sid, sig) }           // consent-id
fn vid(kid: &str, sig: &str) -> String { format!("vid-{}-{}", kid, sig) }           // master-key-vote-id
fn eid(kid: &str, sig: &str) -> String { format!("eid-{}-{}", kid, sig) }           // master-key-id (evidence)

//--------------------------------------------------------------------
// AppDB where the application data results are stored 
//--------------------------------------------------------------------
pub struct AppDB {
    cache: PermaCache,
    local: Db,
    global: Db
}

impl AppDB {
    pub fn new(home: &str) -> Self {
        let local_file = format!("{}/app/local.db", home);
        let global_file = format!("{}/app/global.db", home);

        // nothing to do here, just let it panic
        let local = Db::open(local_file).unwrap();
        let global = Db::open(global_file).unwrap();

        // initialize app-state cache
        let cache = PermaCache::new();
        let state: Option<AppState> = get(&global, STATE)
            .map_err(|e| {
                error!("Unable to get state: {:?}", e);
                format!("Unable to get state: {}", e)
            }).unwrap(); // nothing to do here, just let it panic

        let state = state.unwrap_or_else(|| AppState { height: 0, hash: Vec::<u8>::new() });

        info!("STATE - (height = {:?}, hash = {:?})", state.height, bs58::encode(&state.hash).into_string());
        cache.set(&HASH, state.hash.clone());
        cache.set(&STATE, state);

        Self { cache, local, global }
    }

    // hash and state functions cannot recover from errors.
    pub fn get_hash(&self) -> Vec<u8> {
        self.cache.get(&HASH).unwrap().unwrap()
    }

    // hash and state functions cannot recover from errors.
    pub fn set_state(&self, state: AppState) {
        let data = encode(&state).unwrap();
        self.global.insert(STATE, data).map_err(|e| format!("Unable to save state: {}", e)).unwrap();
        self.global.flush().map_err(|e| format!("Unable to flush state: {}", e)).unwrap();
        
        self.cache.set(&STATE, state);
    }

    // hash and state functions cannot recover from errors.
    pub fn get_state(&self) -> AppState {
        self.cache.get(&STATE).unwrap().unwrap()
    }



    pub fn get_subject(&self, id: &str) -> Result<Option<Subject>> {
        let sid = sid(id);
        get(&self.global, &sid)
    }

    pub fn save_subject(&self, subject: Subject) -> Result<()> {
        let sid = sid(&subject.sid);

        //TODO: how to avoid subject update override
        /*if contains(&self.global, &cid)? {
            return Err("Consent already exists!".into())
        }*/

        let current: Option<Subject> = get(&self.global, &sid)?;
        match current {
            None => set(&self.global, &self.cache, &sid, subject),
            Some(mut current) => {
                current.merge(subject);
                set(&self.global, &self.cache, &sid, current)
            }
        }
    }

    pub fn get_authorizations(&self, sid: &str) -> Result<Authorizations> {
        let aid = aid(sid);

        let auths: Option<Authorizations> = get(&self.global, &aid)?;
        match auths {
            None => Ok(Authorizations::new()),
            Some(obj) => Ok(obj)
        }
    }

    pub fn save_authorization(&self, consent: Consent) -> Result<()> {
        let cid = cid(&consent.sid, consent.sig.id());
        let aid = aid(&consent.sid);

        // avoid consent override
        if contains(&self.global, &cid)? {
            return Err("Consent already exists!".into())
        }

        let mut auths = self.get_authorizations(&consent.sid)?;
        match consent.typ {
            ConsentType::Consent => auths.authorize(&consent),
            ConsentType::Revoke => auths.revoke(&consent)
        }
        
        tx(&self.global, &self.cache, |tx| {
            tx.set(&cid, consent)?;
            tx.set(&aid, auths)
        })
    }

    pub fn get_vote(&self, kid: &str, sig: &str) -> Result<Option<MasterKeyVote>> {
        let vid = vid(kid, sig);
        get(&self.local, &vid)
    }

    pub fn save_vote(&self, vote: MasterKeyVote) -> Result<()> {
        let vid = vid(&vote.kid, vote.sig.id());

        // avoid vote override
        if contains(&self.global, &vid)? {
            return Err("Vote already exists!".into())
        }

        set(&self.local, &self.cache, &vid, vote)
    }

    pub fn get_key(&self, kid: &str) -> Result<Option<MasterKeyPair>> {
        let kid = pid(kid);

        let cached = self.cache.get(&kid)?;
        if cached.is_some() {
            return Ok(cached)
        }

        let mkey: Option<MasterKeyPair> = get(&self.local, &kid)?;
        match mkey {
            None => Ok(None),
            Some(obj) => {
                self.cache.set(&kid, obj.clone());
                Ok(Some(obj))
            }
        }
    }

    pub fn get_key_evidence(&self, kid: &str, sig: &str) -> Result<Option<MasterKey>> {
        let eid = eid(kid, sig);
        get(&self.global, &eid)
    }

    pub fn save_key(&self, evidence: MasterKey, pair: MasterKeyPair) -> Result<()> {
        if evidence.kid != pair.kid {
            // if it executes it's a bug in the code
            error!("Bug detected when executing AppDB::save_key");
            panic!("evidence.kid != pair.kid");
        }

        // evidence keeps history for key
        let eid = eid(&evidence.kid, evidence.sig.id());
        let kid = pid(&pair.kid);

        // avoid evidence override
        if contains(&self.global, &eid)? {
            return Err("Master-key evidence already exists!".into())
        }

        set(&self.global, &self.cache, &eid, evidence)?;
        set(&self.local, &self.cache, &kid, pair)
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

pub struct DbTx<'a> {
    pub tree: &'a TransactionalTree,
    pub state: RefCell<Sha512>
}

impl<'a> DbTx<'a> {
    pub fn new(tree: &'a TransactionalTree, hasher: Sha512) -> Self {
        Self { tree, state: RefCell::new(hasher)}
    }

    pub fn set<T: Serialize>(&self, id: &str, obj: T) -> Result<()> {
        let data = encode(&obj)?;

        // update app state
        let mut value = self.state.borrow_mut();
        value.input(&data);

        self.tree.insert(id, data).map_err(|e| format!("Unable to set structure: {}", e))?;
        Ok(())
    }

    pub fn hash(self) -> Vec<u8> {
        let value = self.state.into_inner();
        value.result().to_vec()
    }
}

fn contains(db: &Db, id: &str) -> Result<bool> {
    db.contains_key(id).map_err(|e| format!("Unable to verify if key exists: {}", e))
}

fn get<T: DeserializeOwned>(db: &Db, id: &str) -> Result<Option<T>> {
    let res: Option<IVec> = db.get(id).map_err(|e| format!("Unable to get structure by id: {}", e))?;
    match res {
        None => Ok(None),
        Some(data) => {
            let obj: T = decode(&data)?;
            Ok(Some(obj))
        }
    }
}

fn set<T: Serialize>(db: &Db, cache: &PermaCache, id: &str, obj: T) -> Result<()> {
    tx(db, cache, |tx| { tx.set(id, obj) })
}

fn tx<T: FnOnce(&DbTx) -> Result<()>>(db: &Db, cache: &PermaCache, commit: T) -> Result<()> {
    // BIG fucking hack so I can call the closure!!!
    let commit = Rc::new(RefCell::new(Some(commit)));
    db.transaction(move |db| {
        let call = commit.borrow_mut().take().unwrap();

        // get current app-state from cache
        let hash: Option<Vec<u8>> = cache.get(&HASH).map_err(|e| {
            error!("tx-abort: {}", e);
            TransactionError::Abort
        })?;

        let mut hasher = Sha512::new();
        if let Some(hash) = &hash {
            hasher.input(hash);
        }

        // execute transactions and chain state
        let db_tx = DbTx::new(db, hasher);
        call(&db_tx).map_err(|e| {
            error!("tx-abort: {}", e);
            TransactionError::Abort
        })?;

        // update cached app-state
        cache.set(&HASH, db_tx.hash());

        Ok(())
    }).map_err(|e| format!("Unable to save structure: {}", e))?;
    db.flush().map_err(|e| format!("Unable to flush: {}", e))?;
    
    Ok(())
}

//--------------------------------------------------------------------
// CacheStore
//--------------------------------------------------------------------
type SafeAny = Any + Send + Sync;

struct PermaCache {
    cache: Mutex<RefCell<HashMap<String, Box<SafeAny>>>>,
}

impl PermaCache {
    fn new() -> Self {
        Self { cache: Mutex::new(RefCell::new(HashMap::new())) }
    }

    fn get<T: Clone + Send + Sync + 'static>(&self, id: &str) -> Result<Option<T>> {
        let guard = self.cache.lock().unwrap();
        let map = guard.borrow();
        let value = map.get(id);

        match value {
            None => Ok(None),
            Some(bv) => {
                let casted = bv.downcast_ref::<T>();
                match casted {
                    Some(res) => Ok(Some(res.clone())),
                    None => Err("Unable to downcast to expected type!".into())
                }
            }
        }
    }

    fn set<T: Clone + Send + Sync + 'static>(&self, id: &str, value: T) {
        let guard = self.cache.lock().unwrap();
        let mut map = guard.borrow_mut();
        map.insert(id.into(), Box::new(value));
    }
}