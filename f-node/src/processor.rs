use std::sync::Arc;

use core_fpi::Result;
use core_fpi::messages::*;

use crate::handlers::keys::*;
use crate::handlers::subjects::*;
use crate::config::Config;

// decode and dispatch messages to the respective handlers
pub struct Processor {
    subject_handler: SubjectHandler,
    mkey_handler: MasterKeyHandler
}

impl Processor {
    pub fn new(cfg: Config) -> Self {
        let cfg = Arc::new(cfg);
        
        Self {
            subject_handler: SubjectHandler::new(),
            mkey_handler: MasterKeyHandler::new(cfg.clone())
        }
    }

    pub fn request(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msg: Request = decode(data)?;
        match msg {
            Request::Negotiate(neg) => match neg {
                Negotiate::NMasterKeyRequest(req) => self.mkey_handler.negotiate(req)
            }
            
        }
    }

    pub fn check(&self, data: &[u8]) -> Result<()> {
        let msg: Commit = decode(data)?;
        match msg {
            Commit::Evidence(evd) => match evd {
                Evidence::EMasterKey(mkey) => self.mkey_handler.check(&mkey)
            },

            Commit::Value(value) => match value {
                Value::VSubject(subject) => self.subject_handler.check(&subject),
                _ => return Err("Not implemented!")
            }
        }
    }

    pub fn commit(&mut self, data: &[u8]) -> Result<()> {
        let msg: Commit = decode(data)?;
        match msg {
            Commit::Evidence(evd) => match evd {
                Evidence::EMasterKey(mkey) => self.mkey_handler.commit(mkey)
            },

            Commit::Value(value) => match value {
                Value::VSubject(subject) => self.subject_handler.commit(subject),
                _ => return Err("Not implemented!")
            }
        }
    }
}