use std::sync::Arc;
use log::info;

use core_fpi::{Result, ID};
use core_fpi::ids::*;
use core_fpi::consents::*;

use crate::databases::AppDB;

pub struct ConsentHandler {
    db: Arc<AppDB>
}

impl ConsentHandler {
    pub fn new(db: Arc<AppDB>) -> Self {
        Self { db }
    }

    pub fn check_consent(&self, consent: &Consent) -> Result<()> {
        info!("CHECK-CONSENT - (id = {:?}, sid = {:?}, auth = {:?}, #profiles = {:?})", consent.id(), consent.sid, consent.authorized, consent.profiles.len());
        
        let current: Subject = self.db.get_subject(&consent.sid)?.ok_or("Subject not found!")?;
        consent.check(&current)
    }

    pub fn check_revoke(&self, revoke: &RevokeConsent) -> Result<()> {
        info!("CHECK-REVOKE - (id = {:?}, sid = {:?}, consent = {:?})", revoke.id(), revoke.sid, revoke.consent);
        
        let current: Subject = self.db.get_subject(&revoke.sid)?.ok_or("Subject not found!")?;
        revoke.check(&current)
    }

    pub fn commit_consent(&mut self, consent: Consent) -> Result<()> {
        //self.check_consent(&consent)?;
        info!("COMMIT-CONSENT - (id = {:?})", consent.id());
        self.db.save_consent(consent)
    }

    pub fn commit_revoke(&mut self, revoke: RevokeConsent) -> Result<()> {
        //self.check_revoke(&revoke)?;
        info!("COMMIT-REVOKE - (id = {:?})", revoke.id());
        self.db.save_revoke(revoke)
    }
}