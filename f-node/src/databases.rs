use std::sync::Mutex;
use std::collections::HashMap;
use log::info;

use core_fpi::Result;
use core_fpi::consents::*;
use core_fpi::ids::*;

//--------------------------------------------------------------------
// LocalDB where local secret are stored
//--------------------------------------------------------------------
pub struct LocalDB {

}

//--------------------------------------------------------------------
// GlobalDB where the consensus results are stored 
//--------------------------------------------------------------------
pub struct GlobalDB {
    subjects: Mutex<HashMap<String, Subject>>
}

impl GlobalDB {
    pub fn new() -> Self {
        Self { subjects: Mutex::new(HashMap::new()) }
    }

    pub fn find(&self, sid: &str) -> Option<Subject> {
        let guard = self.subjects.lock().unwrap();
        
        match guard.get(sid) {
            None => None,
            Some(sub) => Some(sub.clone())
        }
    }

    pub fn update(&self, subject: Subject) -> Result<()> {
        let guard = self.subjects.lock().unwrap();

        let sid = subject.sid.clone();
        let current = guard.remove(&sid);
        match current {
            None => guard.insert(sid, subject),
            Some(mut current) => {
                current.merge(subject);
                info!("UPDATED-SUBJECT - (sid = {:?})", current.sid);
                guard.insert(sid, current)
            }
        };

        Ok(())
    }

    pub fn authorize(&self, consent: Consent) -> Result<()> {
        Ok(())
    }
}