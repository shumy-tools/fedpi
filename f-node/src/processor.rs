use std::sync::Arc;
use log::{info, error};

use core_fpi::Result;
use core_fpi::messages::*;

use crate::handlers::keys::*;
use crate::handlers::subjects::*;
use crate::config::Config;

// decode and log dispatch messages to the respective handlers
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
                Negotiate::NMasterKeyRequest(req) => {
                    info!("REQUEST - Negotiate::NMasterKeyRequest");
                    self.mkey_handler.request(req).map_err(|e|{
                        error!("REQUEST-ERR - Negotiate::NMasterKeyRequest - {:?}", e);
                    e})
                }
            }
        }
    }

    pub fn check(&self, data: &[u8]) -> Result<()> {
        let msg: Commit = decode(data)?;
        match msg {
            Commit::Evidence(evd) => match evd {
                Evidence::EMasterKey(mkey) => {
                    info!("CHECK - Evidence::EMasterKey");
                    self.mkey_handler.check(&mkey).map_err(|e|{
                        error!("CHECK-ERR - Evidence::EMasterKey - {:?}", e);
                    e})
                }
            },

            Commit::Value(value) => match value {
                Value::VSubject(subject) => {
                    info!("CHECK - Value::VSubject");
                    self.subject_handler.check(&subject).map_err(|e|{
                        error!("CHECK-ERR - Value::VSubject - {:?}", e);
                    e})
                },
                _ => Err("Not implemented!")
            }
        }
    }

    pub fn commit(&mut self, data: &[u8]) -> Result<()> {
        let msg: Commit = decode(data)?;
        match msg {
            Commit::Evidence(evd) => match evd {
                Evidence::EMasterKey(mkey) => {
                    info!("COMMIT - Evidence::EMasterKey");
                    self.mkey_handler.commit(mkey).map_err(|e|{
                        error!("COMMIT-ERR - Evidence::EMasterKey - {:?}", e);
                    e})
                }
            },

            Commit::Value(value) => match value {
                Value::VSubject(subject) => {
                    info!("COMMIT - Value::VSubject");
                    self.subject_handler.commit(subject).map_err(|e|{
                        error!("COMMIT-ERR - Value::VSubject - {:?}", e);
                    e})
                },
                _ => Err("Not implemented!")
            }
        }
    }
}