use indexmap::{IndexMap, IndexSet};
use serde::{Serialize, Deserialize};
use std::time::Duration;

use crate::Authenticated;
use crate::ids::*;
use crate::crypto::signatures::IndSignature;
use crate::{Result, Scalar};

//-----------------------------------------------------------------------------------------------------------
// Subject Authorizations
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Authorizations {
    auths: IndexMap<String, IndexSet<String>>       // All profile authorizations per subject <subject: <profile>>
}

impl Authorizations {
    pub fn new() -> Self {
        Self { auths: IndexMap::new() }
    }

    pub fn authorize(&mut self, consent: &Consent) {
        let aid = consent.target.clone();
        let consents = self.auths.entry(aid).or_insert_with(|| IndexSet::<String>::new());
        for item in consent.profiles.iter() {
            consents.insert(item.clone());
        }
    }

    pub fn revoke(&mut self, consent: &Consent) {
        let aid = consent.target.clone();
        if let Some(ref mut consents) = self.auths.get_mut(&aid) {
            for item in consent.profiles.iter() {
                consents.swap_remove(item);
            }

            if consents.is_empty() {
                self.auths.swap_remove(&aid);
            }
        }
    }

    pub fn is_authorized(&self, target: &str, profile: &str) -> bool {
        match self.auths.get(target) {
            None => false,
            Some(t_auths) => t_auths.contains(profile)
        }
    }
}

//-----------------------------------------------------------------------------------------------------------
// Subject Consent/Revoke
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum ConsentType {
    Consent, Revoke
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Consent {
    pub sid: String,                                // Subject-id submitting consent
    pub typ: ConsentType,                           // Consent or revoke
    pub target: String,                             // Authorized data-subject target
    pub profiles: Vec<String>,                      // List of consented profiles (full disclosure)

    pub sig: IndSignature,                          // Signature from data-subject
    #[serde(skip)] _phantom: () // force use of constructor
}

impl Authenticated for Consent {
    fn sid(&self) -> &str { &self.sid }

    fn verify(&self, subject: &Subject, threshold: Duration) -> Result<()> {
        if !self.sig.sig.check_timestamp(threshold) {
            return Err("Timestamp out of valid range!".into())
        }

        let skey = subject.keys.last().ok_or("No active subject-key found!")?;
        let sig_data = Self::data(&self.sid, &self.typ, &self.target, &self.profiles);
        if !self.sig.verify(&skey.key, &sig_data) {
            return Err("Invalid consent signature!".into())
        }

        Ok(())
    }
}

impl Consent {
    pub fn sign(sid: &str, typ: ConsentType, target: &str, profiles: &[String], sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let sig_data = Self::data(sid, &typ, target, profiles);
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, &sig_data);
        
        Self { sid: sid.into(), typ, target: target.into(), profiles: profiles.to_vec(), sig, _phantom: () }
    }

    pub fn check(&self, subject: &Subject) -> Result<()> {
        // check for existing profiles in the subject
        for item in self.profiles.iter() {
            if !subject.profiles.contains_key(item) {
                return Err(format!("No profile found: {}", item))
            }
        }

        Ok(())
    }

    fn data(sid: &str, typ: &ConsentType, target: &str, profiles: &[String]) -> [Vec<u8>; 4] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_sid = bincode::serialize(sid).unwrap();
        let b_typ = bincode::serialize(typ).unwrap();
        let b_target = bincode::serialize(target).unwrap();
        let b_profiles = bincode::serialize(profiles).unwrap();

        [b_sid, b_typ, b_target, b_profiles]
    }
}