use std::sync::Arc;
use log::info;

use core_fpi::Result;
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
        info!("CHECK-SUBJECT - (sid = {:?})", subject.sid);
        
        let current = self.db.find(&subject.sid);
        subject.check(current)
    }

    pub fn commit(&mut self, subject: Subject) -> Result<()> {
        self.check(&subject)?; // TODO: optimize by using local cache?
        info!("COMMIT-SUBJECT - (sid = {:?})", subject.sid);
        
        self.db.update(subject)
    }
}