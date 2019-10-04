use std::sync::Arc;
use log::info;

use core_fpi::Result;
use core_fpi::ids::*;

use crate::databases::AppDB;

pub struct SubjectHandler {
    db: Arc<AppDB>
}

impl SubjectHandler {
    pub fn new(db: Arc<AppDB>) -> Self {
        Self { db }
    }

    pub fn check(&self, subject: &Subject) -> Result<()> {
        info!("CHECK-SUBJECT - (sid = {:?}, #keys = {:?}, #profiles = {:?})", subject.sid, subject.keys.len(), subject.profiles.len());
        let current: Option<Subject> = self.db.get_subject(&subject.sid)?;
        info!("CURRENT - {:#?}", current);
        
        subject.check(current)
    }

    pub fn commit(&mut self, subject: Subject) -> Result<()> {
        //self.check(&subject)?;
        info!("COMMIT-SUBJECT - (sid = {:?})", subject.sid);
        self.db.save_subject(subject)
    }
}