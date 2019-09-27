use std::collections::HashMap;
use log::info;

use core_fpi::Result;
use core_fpi::ids::*;

pub struct SubjectHandler {
    subjects: HashMap<String, Subject>
}

impl SubjectHandler {
    pub fn new() -> Self {
        Self { subjects: HashMap::new() }
    }

    pub fn check(&self, subject: &Subject) -> Result<()> {
        info!("CHECK-SUBJECT - (sid = {:?})", subject.sid);
        
        // TODO: find subject in the database
        let current = self.subjects.get(&subject.sid);
        subject.check(current)
    }

    pub fn commit(&mut self, subject: Subject) -> Result<()> {
        self.check(&subject)?; // TODO: optimize by using local cache?
        info!("COMMIT-SUBJECT - (sid = {:?})", subject.sid);
        
        // TODO: find subject in the database
        let sid = subject.sid.clone();
        let current = self.subjects.remove(&sid);
        match current {
            None => self.subjects.insert(sid, subject),
            Some(mut current) => {
                current.merge(subject);
                info!("MERGED-SUBJECT - (sid = {:?})", current.sid);
                self.subjects.insert(sid, current)
            }
        };

        Ok(())
    }
}