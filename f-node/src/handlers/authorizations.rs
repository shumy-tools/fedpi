use std::sync::Arc;
use log::info;

use core_fpi::Result;
use core_fpi::ids::*;
use core_fpi::authorizations::*;

use crate::db::*;

pub struct AuthorizationHandler {
    store: Arc<AppDB>
}

impl AuthorizationHandler {
    pub fn new(store: Arc<AppDB>) -> Self {
        Self { store }
    }

    pub fn filter(&self, consent: &Consent) -> Result<()> {
        info!("FILTER-CONSENT - (sid = {:?}, typ = {:?}, auth = {:?}, #profiles = {:?})", consent.sid, consent.typ, consent.target, consent.profiles.len());
        
        //TODO: should only verify signatures
        Ok(())
    }

    pub fn deliver(&mut self, consent: Consent) -> Result<()> {
        info!("DELIVER-CONSENT - (sid = {:?})", consent.sid);
        let cid = cid(&consent.sid, consent.sig.id());
        let aid = aid(&consent.sid);

        // ---------------transaction---------------
        let tx = self.store.tx();

            // avoid consent override
            if tx.contains(&cid) {
                return Err("Consent already exists!".into())
            }

            // search for target subject
            let sid = sid(&consent.target);
            let subject: Subject = tx.get(&sid).ok_or("Subject target not found!")?;
            consent.check(&subject)?;

            // create or update authorizations
            let mut auths: Authorizations = tx.get(&aid).unwrap_or_else(|| Authorizations::new());
            match consent.typ {
                ConsentType::Consent => auths.authorize(&consent),
                ConsentType::Revoke => auths.revoke(&consent)
            }
            
            tx.set(&cid, consent);
            tx.set(&aid, auths);
        Ok(())
    }
}