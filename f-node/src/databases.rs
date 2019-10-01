use sled::{Db, IVec, TransactionError, TransactionalTree};
use std::rc::Rc;
use std::cell::RefCell;

use serde::{Serialize, Deserialize};
use log::error;

use core_fpi::{ID, Result};
use core_fpi::ids::*;
use core_fpi::messages::{encode, decode};

//--------------------------------------------------------------------
// LocalDB where local secret are stored
//--------------------------------------------------------------------
/*pub struct LocalDB {

}*/

//--------------------------------------------------------------------
// GlobalDB where the consensus results are stored 
//--------------------------------------------------------------------
pub struct GlobalDB {
    db: Db
}

impl GlobalDB {
    pub fn new(path: &str) -> Self {
        // nothing to do here, just let it panic
        let tree = Db::open(path).unwrap();
        Self { db: tree }
    }

    /*pub fn get<'a, T: Deserialize<'a>>(&self, id: &str) -> Result<Option<T>> {
        let res: Option<IVec> = self.db.get(id).map_err(|e| format!("Unable to get id: {}", e))?;
        match res {
            None => Ok(None),
            Some(data) => {
                let obj: T = decode(&data)?;
                Ok(Some(obj))
            }
        }
    }*/


    pub fn get_subject(&self, id: &str) -> Result<Option<Subject>> {
        let res: Option<IVec> = self.db.get(id).map_err(|e| format!("Unable to get id: {}", e))?;
        match res {
            None => Ok(None),
            Some(data) => {
                let obj: Subject = decode(&data)?;
                Ok(Some(obj))
            }
        }
    }

    /*pub fn get_consent(&self, id: &str) -> Result<Option<Consent>> {
        let res: Option<IVec> = self.db.get(id).map_err(|e| format!("Unable to get id: {}", e))?;
        match res {
            None => Ok(None),
            Some(data) => {
                let obj: Consent = decode(&data)?;
                Ok(Some(obj))
            }
        }
    }*/

    pub fn tx<T: FnOnce(DbTx) -> Result<()>>(&self, commit: T) -> Result<()> {
        // BIG fucking hack so I can call the closure!!!
        let commit = Rc::new(RefCell::new(Some(commit)));
        self.db.transaction(move |db| {
            let call = commit.borrow_mut().take().unwrap();
            call(DbTx(db)).map_err(|e| {
                error!("tx-abort: {}", e);
                TransactionError::Abort
            })?;

            Ok(())
        }).map_err(|e| format!("Unable to save structure: {}", e))
    }

    pub fn set<T: Serialize + ID>(&self, obj: T) -> Result<()> {
        let data = encode(&obj)?;
        self.save(obj.id(), &data)
    }

    pub fn save(&self, id: &str, data: &[u8]) -> Result<()> {
        self.db.insert(id, data).map_err(|e| format!("Unable to save structure: {}", e))?;
        Ok(())
    }
}

pub struct DbTx<'a> (pub &'a TransactionalTree);

impl<'a> DbTx<'a> {
    pub fn set<T: Serialize + ID>(&self, obj: T) -> Result<()> {
        let data = encode(&obj)?;
        self.save(obj.id(), &data)
    }

    pub fn save(&self, id: &str, data: &[u8]) -> Result<()> {
        self.0.insert(id, data).map_err(|e| format!("Unable to save structure: {}", e))?;
        Ok(())
    }
}