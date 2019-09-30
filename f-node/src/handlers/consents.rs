use std::sync::Arc;
use log::info;

use core_fpi::Result;
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
        
        // TODO: find subject in the database
        Ok(())
    }

    pub fn commit(&mut self, consent: Consent) -> Result<()> {
        self.check(&consent)?; // TODO: optimize by using local cache?
        info!("COMMIT-CONSENT - (sid = {:?})", consent.sid);

        Ok(())
    }
}