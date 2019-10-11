use std::sync::Arc;
use std::time::Duration;

use log::{info, error};

use core_fpi::{Result, Constraints};
use core_fpi::ids::*;
use core_fpi::messages::*;

use crate::handlers::keys::*;
use crate::handlers::subjects::*;
use crate::handlers::authorizations::*;
use crate::handlers::disclosures::*;

use crate::config::Config;
use crate::db::*;

const TIMESTAMP_THRESHOLD: u64 = 60;

// decode and log dispatch messages to the respective handlers
pub struct Processor {
    store: Arc<AppDB>,

    mkey_handler: MasterKeyHandler,
    subject_handler: SubjectHandler,
    auth_handler: AuthorizationHandler,
    disclosure_handler: DisclosureHandler
}

impl Processor {
    pub fn new(cfg: Config) -> Self {
        let cfg = Arc::new(cfg);

        let path = format!("{}/data", cfg.home);
        let store = Arc::new(AppDB::new(&path));
        
        Self {
            store: store.clone(),

            mkey_handler: MasterKeyHandler::new(cfg.clone(), store.clone()),
            subject_handler: SubjectHandler::new(store.clone()),
            auth_handler: AuthorizationHandler::new(store.clone()),
            disclosure_handler: DisclosureHandler::new(cfg.clone(), store.clone()),
        }
    }

    pub fn request(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msg: Request = decode(data)?;
        
        // check field constraints, signature and timestamp range
        let sid = sid(msg.sid());
        let subject: Subject = self.store.get(&sid).ok_or("Subject not found!")?;
        msg.verify(&subject, Duration::from_secs(TIMESTAMP_THRESHOLD))?;

        match msg {
            Request::Negotiate(neg) => match neg {
                Negotiate::NMasterKeyRequest(req) => {
                    self.mkey_handler.request(req).map_err(|e|{
                        error!("REQUEST-ERR - Negotiate::NMasterKeyRequest - {:?}", e);
                    e})
                }
            },
            Request::Query(query) => match query {
                Query::QDiscloseRequest(req) => {
                    self.disclosure_handler.request(req).map_err(|e|{
                        error!("REQUEST-ERR - Query::QDiscloseRequest - {:?}", e);
                    e})
                }
            }
        }
    }

    pub fn start(&self) {
        info!("START-BLOCK");
        self.store.start();
    }

    // check signature and timestamp range
    pub fn filter(&self, data: &[u8]) -> Result<()> {
        let msg: Commit = decode(data)?;

        let sid = sid(msg.sid());
        let t_sub: Option<Subject> = self.store.get(&sid);
        let mut subject = t_sub.as_ref();
        
        // handle exception for creation
        if subject.is_none() {
            if let Commit::Value(value) = &msg {
                if let Value::VSubject(sub) = value {
                    subject = Some(sub)
                }
            }
        }

        if subject.is_none() {
            error!("Subject not found!");
            return Err("Subject not found!".into());
        }

        msg.verify(subject.unwrap(), Duration::from_secs(TIMESTAMP_THRESHOLD))
    }

    pub fn deliver(&mut self, data: &[u8]) -> Result<()> {
        let msg: Commit = decode(data)?;
        match msg {
            Commit::Evidence(evd) => match evd {
                Evidence::EMasterKey(mkey) => {
                    info!("DELIVER - Evidence::EMasterKey");
                    self.mkey_handler.deliver(mkey).map_err(|e|{
                        error!("DELIVER-ERR - Evidence::EMasterKey - {:?}", e);
                    e})
                }
            },

            Commit::Value(value) => match value {
                Value::VSubject(subject) => {
                    info!("DELIVER - Value::VSubject");
                    self.subject_handler.deliver(subject).map_err(|e|{
                        error!("DELIVER-ERR - Value::VSubject - {:?}", e);
                    e})
                },
                Value::VConsent(consent) => {
                    info!("DELIVER - Value::VConsent");
                    self.auth_handler.deliver(consent).map_err(|e|{
                        error!("DELIVER-ERR - Value::VConsent - {:?}", e);
                    e})
                },
                _ => Err("Not implemented!".into())
            }
        }
    }

    pub fn commit(&self, height: i64) -> AppState {
        let state = self.store.commit(height);
        info!("COMMIT - (height = {:?}, hash = {:?})", state.height, bs58::encode(&state.hash).into_string());
        state
    }

    pub fn state(&self) -> AppState {
        self.store.state()
    }
}