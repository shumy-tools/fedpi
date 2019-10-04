use std::sync::Arc;
use log::info;

use core_fpi::{Result, ID};
use core_fpi::ids::*;
use core_fpi::authorizations::*;

use crate::databases::AppDB;

pub struct AuthorizationHandler {
    db: Arc<AppDB>
}

impl AuthorizationHandler {
    pub fn new(db: Arc<AppDB>) -> Self {
        Self { db }
    }

    pub fn check(&self, consent: &Consent) -> Result<()> {
        info!("CHECK-CONSENT - (id = {:?}, sid = {:?}, typ = {:?}, auth = {:?}, #profiles = {:?})", consent.id(), consent.sid, consent.typ, consent.target, consent.profiles.len());
        self.db.get_subject(&consent.target)?.ok_or("Subject target not found!")?;
        
        let current: Subject = self.db.get_subject(&consent.sid)?.ok_or("Subject not found!")?;
        consent.check(&current)
    }

    pub fn commit(&mut self, consent: Consent) -> Result<()> {
        //self.check_consent(&consent)?;
        info!("COMMIT-CONSENT - (id = {:?})", consent.id());
        self.db.save_authorization(consent)
    }
}