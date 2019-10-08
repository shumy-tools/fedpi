use std::sync::Arc;

use log::{info, error};

use core_fpi::Result;
use core_fpi::messages::*;

use crate::handlers::keys::*;
use crate::handlers::subjects::*;
use crate::handlers::authorizations::*;
use crate::handlers::queries::*;
use crate::config::Config;
use crate::db::{AppDB, AppState};

// decode and log dispatch messages to the respective handlers
pub struct Processor {
    store: Arc<AppDB>,

    mkey_handler: MasterKeyHandler,
    subject_handler: SubjectHandler,
    auth_handler: AuthorizationHandler,
    query_handler: QueryHandler
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
            query_handler: QueryHandler::new(cfg.clone(), store.clone()),
        }
    }

    pub fn request(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        //TODO: needs transactions from local DB!

        let msg: Request = decode(data)?;
        match msg {
            Request::Negotiate(neg) => match neg {
                Negotiate::NMasterKeyRequest(req) => {
                    info!("REQUEST - Negotiate::NMasterKeyRequest");
                    self.mkey_handler.request(req).map_err(|e|{
                        error!("REQUEST-ERR - Negotiate::NMasterKeyRequest - {:?}", e);
                    e})
                }
            },
            Request::Query(query) => match query {
                Query::QDiscloseRequest(req) => {
                    info!("REQUEST - Query::QDiscloseRequest");
                    self.query_handler.request(req).map_err(|e|{
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

    pub fn filter(&self, data: &[u8]) -> Result<()> {
        let msg: Commit = decode(data)?;
        match msg {
            Commit::Evidence(evd) => match evd {
                Evidence::EMasterKey(mkey) => {
                    info!("FILTER - Evidence::EMasterKey");
                    self.mkey_handler.filter(&mkey).map_err(|e|{
                        error!("FILTER-ERR - Evidence::EMasterKey - {:?}", e);
                    e})
                }
            },

            Commit::Value(value) => match value {
                Value::VSubject(subject) => {
                    info!("FILTER - Value::VSubject");
                    self.subject_handler.filter(&subject).map_err(|e|{
                        error!("FILTER-ERR - Value::VSubject - {:?}", e);
                    e})
                },
                Value::VConsent(consent) => {
                    info!("FILTER - Value::VConsent");
                    self.auth_handler.filter(&consent).map_err(|e|{
                        error!("FILTER-ERR - Value::VConsent - {:?}", e);
                    e})
                },
                _ => Err("Not implemented!".into())
            }
        }
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