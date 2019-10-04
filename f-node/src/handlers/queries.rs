use std::sync::Arc;
use log::info;

use core_fpi::Result;
use core_fpi::disclosures::*;
use core_fpi::messages::*;

use crate::config::Config;
use crate::databases::{MASTER, AppDB};

pub struct QueryHandler {
    cfg: Arc<Config>,
    db: Arc<AppDB>
}

impl QueryHandler {
    pub fn new(cfg: Arc<Config>, db: Arc<AppDB>) -> Self {
        Self { cfg, db }
    }

    pub fn request(&mut self, disclose: DiscloseRequest) -> Result<Vec<u8>> {
        info!("REQUEST-DISCLOSE - (sid = {:?}, target = {:?}, #profiles = {:?})", disclose.sid, disclose.target, disclose.profiles.len());

        let subject = self.db.get_subject(&disclose.sid)?.ok_or("Subject not found!")?;
        disclose.check(&subject)?;

        let mkey = self.db.get_key(MASTER)?.ok_or("Master-key unavailable!")?;
        let target = self.db.get_subject(&disclose.target)?.ok_or("Target not found!")?;
        let auths = self.db.get_authorizations(&disclose.target)?;

        // verify if the client has authorization to disclose profiles
        let mut dkeys = DiscloseKeys::new();
        for typ in disclose.profiles.iter() {
            if !auths.is_authorized(&disclose.sid, typ) {
                return Err(format!("Subject has not authorization for profile: {}", typ))
            }

            let prof = target.profiles.get(typ).ok_or("Bug in code. No profile found, but there is an authorization!")?;
            for (_, loc) in prof.locations.iter() {
                for pkey in loc.chain.iter() {
                    let pseudo_i = &mkey.share * &pkey.key;
                    dkeys.put(&typ, &loc.lurl, pseudo_i);
                }
            }
        }

        let res = DiscloseResult::sign(&disclose.sig.sig.encoded, dkeys, &self.cfg.secret, &self.cfg.pkey, self.cfg.index);
        let msg = Response::QResult(QResult::QDiscloseResult(res));
        encode(&msg)
    }
}