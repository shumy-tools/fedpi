use std::sync::Arc;
use log::info;

use core_fpi::Result;
use core_fpi::ids::*;
use core_fpi::consents::*;

use crate::databases::*;

pub struct ConsentHandler {
    db: Arc<GlobalDB>
}

impl ConsentHandler {
    pub fn new(db: Arc<GlobalDB>) -> Self {
        Self { db }
    }

    pub fn check_consent(&self, consent: &Consent) -> Result<()> {
        info!("CHECK-CONSENT - (sid = {:?})", consent.sid);
        
        let current: Subject = self.db.get_subject(&consent.sid)?.ok_or("Subject not found!")?;
        consent.check(&current)
    }

    pub fn check_revoke(&self, revoke: &RevokeConsent) -> Result<()> {
        info!("CHECK-REVOKE - (sid = {:?})", revoke.sid);
        
        let current: Subject = self.db.get_subject(&revoke.sid)?.ok_or("Subject not found!")?;
        revoke.check(&current)
    }

    pub fn commit_consent(&mut self, consent: Consent) -> Result<()> {
        //self.check_consent(&consent)?;
        info!("COMMIT-CONSENT - (sid = {:?})", consent.sid);

        let mut current: Subject = self.db.get_subject(&consent.sid)?.ok_or("Subject not found!")?;
        current.authorize(&consent);
        
        self.db.tx(|tx| {
            tx.set(consent)?;
            tx.set(current)?;
            Ok(())
        })
    }

    pub fn commit_revoke(&mut self, revoke: RevokeConsent) -> Result<()> {
        //self.check_revoke(&revoke)?;
        info!("COMMIT-REVOKE - (sid = {:?})", revoke.sid);

        let consent: Consent = self.db.get_consent(&revoke.consent)?.ok_or("Consent not found!")?;
        let mut current: Subject = self.db.get_subject(&revoke.sid)?.ok_or("Subject not found!")?;
        current.revoke(&consent);
        
        self.db.tx(|tx| {
            tx.set(revoke)?;
            tx.set(current)?;
            Ok(())
        })
    }
}