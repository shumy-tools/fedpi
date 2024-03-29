use std::sync::Arc;
use log::info;

use core_fpi::Result;
use core_fpi::ids::*;

use crate::db::*;

pub struct SubjectHandler {
    store: Arc<AppDB>
}

impl SubjectHandler {
    pub fn new(store: Arc<AppDB>) -> Self {
        Self { store }
    }

    pub fn deliver(&mut self, subject: Subject) -> Result<()> {
        info!("DELIVER-SUBJECT - (sid = {:?}, #keys = {:?}, #profiles = {:?})", subject.sid, subject.keys.len(), subject.profiles.len());
        let sid = sid(&subject.sid);

        // ---------------transaction---------------
        let tx = self.store.tx();
            // check signatures and constraints
            let current: Option<Subject> = tx.get(&sid);
            subject.check(&current)?;

            match current {
                None => tx.set(&sid, subject),
                Some(mut current) => {
                    current.merge(subject);
                    tx.set(&sid, current)
                }
            }
        
        Ok(())
    }
}