use std::collections::HashMap;
use std::rc::Rc;
use std::any::Any;
use std::cell::RefCell;
use std::sync::Mutex;

use serde::Serialize;
use serde::de::DeserializeOwned;

use sled::{Db, IVec, TransactionError, TransactionalTree};
use log::error;

use core_fpi::Result;
use core_fpi::ids::*;
use core_fpi::keys::*;
use core_fpi::authorizations::*;
use core_fpi::messages::{encode, decode};

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
        let res: Option<IVec> = self.global.get(sid).map_err(|e| format!("Unable to get subject by sid: {}", e))?;
        match res {
            None => Ok(None),
            Some(data) => {
                let obj: Subject = decode(&data)?;
                Ok(Some(obj))
            }
        }
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

        let res: Option<IVec> = self.global.get(aid).map_err(|e| format!("Unable to get authorizations for sid: {}", e))?;
        match res {
            None => Ok(Authorizations::new(sid)),
            Some(data) => {
                let obj: Authorizations = decode(&data)?;
                Ok(obj)
            }
        }
    }

    pub fn save_authorization(&self, consent: Consent) -> Result<()> {
        let cid = Consent::id(&consent.sid, &consent.target);
        let aid = Authorizations::id(&consent.sid);        

        let mut auths = self.get_authorizations(&aid)?;
        match consent.typ {
            ConsentType::Consent => auths.authorize(&consent),
            ConsentType::Revoke => auths.revoke(&consent)
        }
        
        tx(&self.global, |tx| {
            tx.set(&cid, consent)?;
            tx.set(&aid, auths)?;
            Ok(())
        })
    }

    pub fn get_vote(&self, session: &str, kid: &str) -> Result<Option<MasterKeyVote>> {
        let vid = MasterKeyVote::id(session, kid);

        let res: Option<IVec> = self.local.get(vid).map_err(|e| format!("Unable to get vote by id: {}", e))?;
        match res {
            None => Ok(None),
            Some(data) => {
                let obj: MasterKeyVote = decode(&data)?;
                Ok(Some(obj))
            }
        }
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

        let res: Option<IVec> = self.local.get(&kid).map_err(|e| format!("Unable to get master-key by id: {}", e))?;
        match res {
            None => Ok(None),
            Some(data) => {
                let obj: MasterKeyPair = decode(&data)?;
                self.cache.set(&kid, obj.clone());
                Ok(Some(obj))
            }
        }
    }

    pub fn save_key(&self, evidence: MasterKey, pair: MasterKeyPair) -> Result<()> {
        if evidence.kid != pair.kid {
            // if it executes it's a bug in the code
            panic!("evidence.kid != pair.kid");
        }

        let eid = MasterKey::id(&evidence.session, &evidence.kid);
        let kid = MasterKeyPair::id(&pair.kid);

        set(&self.global, &eid, evidence)?;
        set(&self.local, &kid, pair)
    }
}




//--------------------------------------------------------------------
// Generic database functions and structures
//--------------------------------------------------------------------
pub struct DbTx<'a> (pub &'a TransactionalTree);

impl<'a> DbTx<'a> {
    pub fn set<T: Serialize>(&self, id: &str, obj: T) -> Result<()> {
        let data = encode(&obj)?;
        self.save(id, &data)
    }

    pub fn save(&self, id: &str, data: &[u8]) -> Result<()> {
        self.0.insert(id, data).map_err(|e| format!("Unable to save structure: {}", e))?;
        Ok(())
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
    let data = encode(&obj)?;
    db.insert(id, data).map_err(|e| format!("Unable to insert structure: {}", e))?;
    db.flush().map_err(|e| format!("Unable to flush: {}", e))?;
    Ok(())
}

fn tx<T: FnOnce(DbTx) -> Result<()>>(db: &Db, commit: T) -> Result<()> {
    // BIG fucking hack so I can call the closure!!!
    let commit = Rc::new(RefCell::new(Some(commit)));
    db.transaction(move |db| {
        let call = commit.borrow_mut().take().unwrap();
        call(DbTx(db)).map_err(|e| {
            error!("tx-abort: {}", e);
            TransactionError::Abort
        })?;

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