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

    pub fn deliver(&mut self, consent: Consent) -> Result<()> {
        info!("DELIVER-CONSENT -  (sid = {:?}, typ = {:?}, auth = {:?}, #profiles = {:?})", consent.sid, consent.typ, consent.target, consent.profiles.len());
        let tid = sid(&consent.target);
        let sid = sid(&consent.sid);

        let cid = cid(&consent.sid, consent.sig.id());
        let aid = aid(&consent.sid);

        // ---------------transaction---------------
        let tx = self.store.tx();
            // check constraints
            let subject: Subject = tx.get(&sid).ok_or("Subject not found!")?;
            consent.check(&subject)?;
            
            // avoid consent override
            if tx.contains(&cid) {
                return Err("Consent already exists!".into())
            }

            // search for target subject and check
            if !tx.contains(&tid) {
                return Err("No target subject found!".into())
            }

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
