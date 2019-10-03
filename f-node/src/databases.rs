use sled::{Db, IVec, TransactionError, TransactionalTree};
use std::rc::Rc;
use std::cell::RefCell;

use serde::Serialize;
use log::error;

use core_fpi::{ID, Result};
use core_fpi::ids::*;
use core_fpi::consents::*;
use core_fpi::keys::*;
use core_fpi::messages::{encode, decode};

pub const MASTER: &str = "master";

//--------------------------------------------------------------------
// AppDB where the application data results are stored 
//--------------------------------------------------------------------
pub struct AppDB {
    local: Db,
    global: Db
}

impl AppDB {
    pub fn new(home: &str) -> Self {
        let local_file = format!("{}/app_local.db", home);
        let global_file = format!("{}/app_global.db", home);

        // nothing to do here, just let it panic
        Self {
            local: Db::open(local_file).unwrap(),
            global: Db::open(global_file).unwrap()
        }
    }

    pub fn get_subject(&self, id: &str) -> Result<Option<Subject>> {
        let res: Option<IVec> = self.global.get(id).map_err(|e| format!("Unable to get subject by id: {}", e))?;
        match res {
            None => Ok(None),
            Some(data) => {
                let obj: Subject = decode(&data)?;
                Ok(Some(obj))
            }
        }
    }

    pub fn get_consent(&self, id: &str) -> Result<Option<Consent>> {
        let res: Option<IVec> = self.global.get(id).map_err(|e| format!("Unable to get consent by id: {}", e))?;
        match res {
            None => Ok(None),
            Some(data) => {
                let obj: Consent = decode(&data)?;
                Ok(Some(obj))
            }
        }
    }

    pub fn get_vote(&self, id: &str) -> Result<Option<MasterKeyVote>> {
        let res: Option<IVec> = self.local.get(id).map_err(|e| format!("Unable to get vote by id: {}", e))?;
        match res {
            None => Ok(None),
            Some(data) => {
                let obj: MasterKeyVote = decode(&data)?;
                Ok(Some(obj))
            }
        }
    }

    pub fn get_key(&self, id: &str) -> Result<Option<MasterKeyPair>> {
        let res: Option<IVec> = self.local.get(id).map_err(|e| format!("Unable to get master-key by id: {}", e))?;
        match res {
            None => Ok(None),
            Some(data) => {
                let obj: MasterKeyPair = decode(&data)?;
                Ok(Some(obj))
            }
        }
    }

    pub fn save_subject(&self, subject: Subject) -> Result<()> {
        let id = &subject.id();
        let current: Option<Subject> = self.get_subject(id)?;
        match current {
            None => self.global_save(id, subject),
            Some(mut current) => {
                current.merge(subject);
                self.global_save(id, current)
            }
        }
    }

    pub fn save_consent(&self, consent: Consent) -> Result<()> {
        let mut current: Subject = self.get_subject(&consent.sid)?.ok_or("Subject not found!")?;
        current.authorize(&consent);
        
        self.global_tx(|tx| {
            tx.set(consent)?;
            tx.set(current)?;
            Ok(())
        })
    }

    pub fn save_revoke(&self, revoke: RevokeConsent) -> Result<()> {
        let consent: Consent = self.get_consent(&revoke.consent)?.ok_or("Consent not found!")?;
        let mut current: Subject = self.get_subject(&revoke.sid)?.ok_or("Subject not found!")?;
        current.revoke(&consent);
        
        self.global_tx(|tx| {
            tx.set(revoke)?;
            tx.set(current)?;
            Ok(())
        })
    }

    pub fn save_vote(&self, vote: MasterKeyVote) -> Result<()> {
        self.local_save(&vote.id(), vote)
    }

    pub fn save_key(&self, evidence: MasterKey, pair: MasterKeyPair) -> Result<()> {
        self.global_save(&evidence.id(), evidence)?;
        self.local_save(&pair.id(), pair)
    }



    /*fn local_tx<T: FnOnce(DbTx) -> Result<()>>(&self, commit: T) -> Result<()> {
        // BIG fucking hack so I can call the closure!!!
        let commit = Rc::new(RefCell::new(Some(commit)));
        self.local.transaction(move |db| {
            let call = commit.borrow_mut().take().unwrap();
            call(DbTx(db)).map_err(|e| {
                error!("tx-abort: {}", e);
                TransactionError::Abort
            })?;

            Ok(())
        }).map_err(|e| format!("Unable to save structure: {}", e))?;

        self.local.flush().map_err(|e| format!("Unable to flush: {}", e))?;
        Ok(())
    }*/

    fn global_tx<T: FnOnce(DbTx) -> Result<()>>(&self, commit: T) -> Result<()> {
        // BIG fucking hack so I can call the closure!!!
        let commit = Rc::new(RefCell::new(Some(commit)));
        self.global.transaction(move |db| {
            let call = commit.borrow_mut().take().unwrap();
            call(DbTx(db)).map_err(|e| {
                error!("tx-abort: {}", e);
                TransactionError::Abort
            })?;

            Ok(())
        }).map_err(|e| format!("Unable to save structure: {}", e))?;

        self.global.flush().map_err(|e| format!("Unable to flush: {}", e))?;
        Ok(())
    }

    fn local_save<T: Serialize + ID>(&self, id: &str, obj: T) -> Result<()> {
        let data = encode(&obj)?;
        self.local.insert(id, data).map_err(|e| format!("Unable to insert structure: {}", e))?;
        self.local.flush().map_err(|e| format!("Unable to flush: {}", e))?;
        Ok(())
    }

    fn global_save<T: Serialize + ID>(&self, id: &str, obj: T) -> Result<()> {
        let data = encode(&obj)?;
        self.global.insert(id, data).map_err(|e| format!("Unable to insert structure: {}", e))?;
        self.global.flush().map_err(|e| format!("Unable to flush: {}", e))?;
        Ok(())
    }
}

pub struct DbTx<'a> (pub &'a TransactionalTree);

impl<'a> DbTx<'a> {
    pub fn set<T: Serialize + ID>(&self, obj: T) -> Result<()> {
        let data = encode(&obj)?;
        self.save(&obj.id(), &data)
    }

    pub fn save(&self, id: &str, data: &[u8]) -> Result<()> {
        self.0.insert(id, data).map_err(|e| format!("Unable to save structure: {}", e))?;
        Ok(())
    }
}