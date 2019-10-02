use std::sync::Arc;
use log::info;

use core_fpi::{ID, Result};
use core_fpi::ids::*;

use crate::databases::*;

pub struct SubjectHandler {
    db: Arc<GlobalDB>
}

impl SubjectHandler {
    pub fn new(db: Arc<GlobalDB>) -> Self {
        Self { db }
    }

    pub fn check(&self, subject: &Subject) -> Result<()> {
        info!("CHECK-SUBJECT - (id = {:?}, #keys = {:?}, #profiles = {:?}, #auths = {:?})", subject.id(), subject.keys.len(), subject.profiles.len(), subject.authorizations.len());
        
        let current: Option<Subject> = self.db.get_subject(subject.id())?;
        subject.check(current)
    }

    pub fn commit(&mut self, subject: Subject) -> Result<()> {
        //self.check(&subject)?;
        info!("COMMIT-SUBJECT - (id = {:?})", subject.id());
        
        let current: Option<Subject> = self.db.get_subject(subject.id())?;
        match current {
            None => self.db.set(subject),
            Some(mut current) => {
                current.merge(subject);
                self.db.set(current)
            }
        }
    }
}