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

    pub fn check(&self, consent: &Consent) -> Result<()> {
        info!("CHECK-CONSENT - (sid = {:?})", consent.sid);
        
        let current: Subject = self.db.get_subject(&consent.sid)?.ok_or("Subject not found!")?;
        consent.check(&current)
    }

    pub fn commit(&mut self, consent: Consent) -> Result<()> {
        self.check(&consent)?; // TODO: optimize by using local cache?
        info!("COMMIT-CONSENT - (sid = {:?})", consent.sid);

        let mut current: Subject = self.db.get_subject(&consent.sid)?.ok_or("Subject not found!")?;
        current.authorize(&consent);
        
        self.db.tx(|tx| {
            tx.set(consent)?;
            tx.set(current)?;
            Ok(())
        })
    }
}