use std::sync::Arc;
use log::info;

use core_fpi::Result;
use core_fpi::disclosures::*;
use core_fpi::authorizations::*;
use core_fpi::messages::*;
use core_fpi::ids::*;

use crate::config::Config;
use crate::db::*;

pub struct DisclosureHandler {
    cfg: Arc<Config>,
    store: Arc<AppDB>
}

impl DisclosureHandler {
    pub fn new(cfg: Arc<Config>, store: Arc<AppDB>) -> Self {
        Self { cfg, store }
    }

    pub fn request(&mut self, disclose: DiscloseRequest) -> Result<Vec<u8>> {
        info!("REQUEST-DISCLOSE - (sid = {:?}, target = {:?}, #profiles = {:?})", disclose.sid, disclose.target, disclose.profiles.len());
        let tid = sid(&disclose.target);
        let aid = aid(&disclose.target);

        let pmkey = self.store.key(PMASTER).ok_or("Pseudonym master-key unavailable!")?;
        let emkey = self.store.key(EMASTER).ok_or("Encryption master-key unavailable!")?;

        let target: Subject = self.store.get(&tid).ok_or("No target subject found!")?;
        let auths: Authorizations = self.store.get(&aid).ok_or("No authorizations found for target!")?;

        // verify if the client has authorization to disclose profiles
        let mut dkeys = DiscloseKeys::new();
        for typ in disclose.profiles.iter() {
            if disclose.sid != disclose.target && !auths.is_authorized(&disclose.sid, typ) {
                return Err(format!("Subject has not authorization to disclose profile: {}", typ))
            }

            let prof = target.profiles.get(typ).ok_or("No profile found, but there is an authorization!")?;
            for (_, loc) in prof.locations.iter() {
                for pkey in loc.chain.iter() {
                    let pseudo_i = &pmkey.share * &pkey.pkey;
                    
                    let encryp_i = match pkey.encrypted {
                        true => Some(&emkey.share * &pkey.pkey),
                        false => None
                    };

                    dkeys.put(&typ, &loc.lurl, (pseudo_i, encryp_i));
                }
            }
        }

        let res = DiscloseResult::sign(&disclose.sig.sig.encoded, dkeys, &self.cfg.secret, &self.cfg.pkey, self.cfg.index);
        let msg = Response::QResult(QResult::QDiscloseResult(res));
        
        // store local evidence
        let did = did(&disclose.sid, disclose.sig.id());
        self.store.set_local(&did, disclose);
        
        encode(&msg)
    }
}