use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

use crate::ids::*;
use crate::crypto::signatures::IndSignature;
use crate::crypto::shares::RistrettoShare;
use crate::{Result, Scalar, RistrettoPoint};

//-----------------------------------------------------------------------------------------------------------
// Disclose Request
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscloseRequest {
    pub sid: String,                                // Subject-id requesting disclosure
    pub target: String,                             // Target subject-id for the profiles
    pub profiles: Vec<String>,                      // List of profiles for full disclose
    
    pub sig: IndSignature,                          // Signature from data-subject
    #[serde(skip)] _phantom: () // force use of constructor
}

impl DiscloseRequest {
    pub fn sign(sid: &str, target: &str, profiles: &[String], sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let sig_data = Self::data(sid, target, profiles);
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, &sig_data);
        
        Self { sid: sid.into(), target: target.into(), profiles: profiles.to_vec(), sig, _phantom: () }
    }

    pub fn check(&self, subject: &Subject) -> Result<()> {
        let skey = subject.keys.last().ok_or("No active subject-key found!")?;
        let sig_data = Self::data(&self.sid, &self.target, &self.profiles);
        if !self.sig.verify(&skey.key, &sig_data) {
            return Err("Invalid disclose-request signature!".into())
        }

        Ok(())
    }

    fn data(sid: &str, target: &str, profiles: &[String]) -> [Vec<u8>; 3] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_sid = bincode::serialize(sid).unwrap();
        let b_target = bincode::serialize(target).unwrap();
        let b_profiles = bincode::serialize(profiles).unwrap();

        [b_sid, b_target, b_profiles]
    }
}

//-----------------------------------------------------------------------------------------------------------
// Disclose Result
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscloseResult {
    pub disclose: String,                           // Identifies the disclose by the encoded signature
    pub keys: DiscloseKeys,                         // MPC result

    pub sig: IndSignature,                          // Signature from peer
    #[serde(skip)] _phantom: () // force use of constructor
}

impl DiscloseResult {
    pub fn sign(disclose: &str, keys: DiscloseKeys, secret: &Scalar, key: &RistrettoPoint, index: usize) -> Self {
        let sig_data = Self::data(disclose, &keys);
        let sig = IndSignature::sign(index, secret, &key, &sig_data);
        
        Self { disclose: disclose.into(), keys, sig, _phantom: () }
    }

    pub fn check(&self, disclose: &str, profiles: &[String], key: &RistrettoPoint) -> Result<()> {
        if self.disclose != disclose {
            return Err("DiscloseResult, expected the same disclose-id!".into())
        }

        if !self.keys.constains_the_same(profiles) {
            return Err("DiscloseResult, expected the same profile list!".into())
        }

        let sig_data = Self::data(&self.disclose, &self.keys);
        if !self.sig.verify(&key, &sig_data) {
            return Err("Invalid disclose-result signature!".into())
        }

        Ok(())
    }
    
    fn data(disclose: &str, keys: &DiscloseKeys) -> [Vec<u8>; 2] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_disclose = bincode::serialize(disclose).unwrap();
        let b_keys = bincode::serialize(keys).unwrap();

        [b_disclose, b_keys]
    }
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct DiscloseKeys {
    pub keys: BTreeMap<String, BTreeMap<String, Vec<RistrettoShare>>>,     //MPC result <type <lurl <share>>>
}

impl DiscloseKeys {
    pub fn new() -> Self {
        Self { ..Default::default() }
    }

    pub fn put(&mut self, typ: &str, loc: &str, share: RistrettoShare) {
        let typs = self.keys.entry(typ.into()).or_insert_with(|| BTreeMap::<String, Vec<RistrettoShare>>::new());
        let locs = typs.entry(loc.into()).or_insert_with(|| Vec::<RistrettoShare>::new());
        locs.push(share);
    }

    pub fn constains_the_same(&self, profiles: &[String]) -> bool {
        if profiles.len() != self.keys.len() {
            return false
        }

        for item in profiles.iter() {
            if !self.keys.contains_key(item) {
                return false
            }
        }

        true
    }
}