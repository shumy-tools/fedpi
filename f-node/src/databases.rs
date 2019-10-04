use std::collections::HashMap;
use std::rc::Rc;
use std::any::Any;
use std::cell::RefCell;
use std::sync::Mutex;

use serde::Serialize;
use serde::de::DeserializeOwned;

use sled::{Db, IVec, TransactionError, TransactionalTree};
use sha2::{Sha512, Digest};
use log::error;

use core_fpi::Result;
use core_fpi::ids::*;
use core_fpi::keys::*;
use core_fpi::authorizations::*;
use core_fpi::messages::{encode, decode};

pub const STATE: &str = "state";
pub const MASTER: &str = "master";

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
        Self {
            cache: PermaCache::new(),
            local: Db::open(local_file).unwrap(),
            global: Db::open(global_file).unwrap()
        }
    }

    pub fn get_subject(&self, sid: &str) -> Result<Option<Subject>> {
        get(&self.global, sid)
    }

    pub fn save_subject(&self, subject: Subject) -> Result<()> {
        let sid = subject.sid.clone();

        let current: Option<Subject> = self.get_subject(&sid)?;
        match current {
            None => set(&self.global, &sid, subject),
            Some(mut current) => {
                current.merge(subject);
                set(&self.global, &sid, current)
            }
        }
    }

    pub fn get_authorizations(&self, sid: &str) -> Result<Authorizations> {
        let aid = Authorizations::id(sid);

        let auths: Option<Authorizations> = get(&self.global, &aid)?;
        match auths {
            None => Ok(Authorizations::new(sid)),
            Some(obj) => Ok(obj)
        }
    }

    pub fn save_authorization(&self, consent: Consent) -> Result<()> {
        let cid = Consent::id(&consent.sid, &consent.target);
        let aid = Authorizations::id(&consent.sid);

        let mut auths = self.get_authorizations(&consent.sid)?;
        match consent.typ {
            ConsentType::Consent => auths.authorize(&consent),
            ConsentType::Revoke => auths.revoke(&consent)
        }
        
        tx(&self.global, |tx| {
            tx.set(&cid, consent)?;
            tx.set(&aid, auths)
        })
    }

    pub fn get_vote(&self, session: &str, kid: &str) -> Result<Option<MasterKeyVote>> {
        let vid = MasterKeyVote::id(session, kid);
        get(&self.local, &vid)
    }

    pub fn save_vote(&self, vote: MasterKeyVote) -> Result<()> {
        let vid = MasterKeyVote::id(&vote.session, &vote.kid);
        set(&self.local, &vid, vote)
    }

    pub fn get_key(&self, kid: &str) -> Result<Option<MasterKeyPair>> {
        let kid = MasterKeyPair::id(&kid);

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

    pub fn get_key_evidence(&self, session: &str, kid: &str) -> Result<Option<MasterKey>> {
        let eid = MasterKey::id(&session, &kid);
        get(&self.global, &eid)
    }

    pub fn save_key(&self, evidence: MasterKey, pair: MasterKeyPair) -> Result<()> {
        if evidence.kid != pair.kid {
            // if it executes it's a bug in the code
            error!("Bug detected when executing AppDB::save_key");
            panic!("evidence.kid != pair.kid");
        }

        // evidence keeps history for key
        let eid = MasterKey::id(&evidence.session, &evidence.kid);
        let kid = MasterKeyPair::id(&pair.kid);

        set(&self.global, &eid, evidence)?;
        set(&self.local, &kid, pair)
    }
}




//--------------------------------------------------------------------
// Generic database functions and structures
//--------------------------------------------------------------------
pub struct DbTx<'a> {
    pub tree: &'a TransactionalTree,
    pub state: Mutex<RefCell<Option<Vec<u8>>>>
}

impl<'a> DbTx<'a> {
    pub fn new(tree: &'a TransactionalTree) -> Self {
        Self { tree, state: Mutex::new(RefCell::new(None))}
    }

    pub fn set<T: Serialize>(&self, id: &str, obj: T) -> Result<()> {
        if id == STATE {
            return Err(format!("Cannot use reserved key {:?}!", STATE))
        }

        let data = encode(&obj)?;

        // update app state---------------------------
        let mut hasher = Sha512::new();
        hasher.input(&data);
        {
            let guard = self.state.lock().unwrap();
            let mut value = guard.borrow_mut();
            if let Some(c_state) = value.as_ref() {
                hasher.input(c_state);
            }
            *value = Some(hasher.result().to_vec());
        }
        // update app state---------------------------

        self.tree.insert(id, data).map_err(|e| format!("Unable to set structure: {}", e))?;
        Ok(())
    }

    pub fn state(self) -> Option<Vec<u8>> {
        let guard = self.state.lock().unwrap();
        let mut value = guard.borrow_mut();
        value.take()
    }
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

fn set<T: Serialize>(db: &Db, id: &str, obj: T) -> Result<()> {
    tx(db, |tx| { tx.set(id, obj) })
}

fn tx<T: FnOnce(&DbTx) -> Result<()>>(db: &Db, commit: T) -> Result<()> {
    // BIG fucking hack so I can call the closure!!!
    let commit = Rc::new(RefCell::new(Some(commit)));
    db.transaction(move |db| {
        let call = commit.borrow_mut().take().unwrap();
        
        let db_tx = DbTx::new(db);
        call(&db_tx).map_err(|e| {
            error!("tx-abort: {}", e);
            TransactionError::Abort
        })?;

        // update app-state
        if let Some(state) = db_tx.state() {
            db.insert(STATE, state)?;
        }
        
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