use std::collections::HashMap;

use log::info;

use core_fpi::{KeyEncoder, Result};
use core_fpi::ids::*;
use core_fpi::messages::*;
use core_fpi::messages::Message::*;

use crate::config::Config;

pub struct Processor {
    config: Config,
    subjects: HashMap<String, Subject>
}

impl Processor {
    pub fn new(config: Config) -> Self {
        Self { config: config, subjects: HashMap::new() }
    }

    pub fn validate(&self, data: &[u8]) -> Result<()> {
        let msg = decode(data)?;
        match msg {
            SyncSubject(subject) => self.check_subject(&subject),
            CreateRecord{ record, key, base } => {
                info!("CreateRecord - ({:#?} {:?} {:?})", record, key.encode(), base.encode());
                Ok(())
            }
        }
    }

    pub fn commit(&mut self, data: &[u8]) -> Result<()> {
        let msg = decode(data)?;
        match msg {
            SyncSubject(subject) => self.commit_subject(subject),
            CreateRecord{ record, key, base } => {
                info!("CreateRecord - ({:#?} {:?} {:?})", record, key.encode(), base.encode());
                Ok(())
            }
        }
    }

    fn check_subject(&self, subject: &Subject) -> Result<()> {
        info!("check-subject - {:#?}", subject);
        
        // TODO: find subject in the database
        let current = self.subjects.get(&subject.sid);
        subject.check(current)
    }

    fn commit_subject(&mut self, subject: Subject) -> Result<()> {
        self.check_subject(&subject)?; // TODO: optimize by using local cache?
        info!("commit-subject - {:#?}", subject);
        
        // TODO: find subject in the database
        let sid = subject.sid.clone();
        let current = self.subjects.remove(&sid);
        match current {
            None => self.subjects.insert(sid, subject),
            Some(mut current) => {
                current.merge(subject);
                info!("merged-subject - {:#?}", current);
                self.subjects.insert(sid, current)
            }
        };

        Ok(())
    }
}