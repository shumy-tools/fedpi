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

    pub fn check(&self, consent: &Consent) -> Result<()> {
        info!("CHECK-CONSENT - (id = {:?}, sid = {:?}, typ = {:?}, auth = {:?}, #profiles = {:?})", consent.id(), consent.sid, consent.typ, consent.authorized, consent.profiles.len());
        
        let current: Subject = self.db.get_subject(&consent.sid)?.ok_or("Subject not found!")?;
        consent.check(&current)
    }

    pub fn commit(&mut self, consent: Consent) -> Result<()> {
        //self.check_consent(&consent)?;
        info!("COMMIT-CONSENT - (id = {:?})", consent.id());
        match consent.typ {
            ConsentType::Consent => self.db.save_consent(consent),
            ConsentType::Revoke => self.db.save_revoke(consent)
        }
    }
}