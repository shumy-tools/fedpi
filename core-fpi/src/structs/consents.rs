use serde::{Serialize, Deserialize};

use crate::ids::*;
use crate::crypto::signatures::IndSignature;
use crate::{Result, ID, Scalar};

//-----------------------------------------------------------------------------------------------------------
// Subject Consent
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Consent {
    pub sid: String,                                // Subject-id submitting consent
    pub authorized: String,                         // Authorized data-subject
    pub profiles: Vec<String>,                      // List of consented profiles (full disclosure)

    pub sig: IndSignature,                          // Signature from data-subject
    #[serde(skip)] _phantom: () // force use of constructor
}

impl ID for Consent {
    fn id(&self) -> String {
        self.sig.sig.encoded.clone()
    }
}

impl Consent {
    pub fn sign(sid: &str, authorized: &str, profiles: &[String], sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let sig_data = Self::data(sid, authorized, profiles);
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, &sig_data);
        
        Self { sid: sid.into(), authorized: authorized.into(), profiles: profiles.to_vec(), sig, _phantom: () }
    }

    pub fn check(&self, subject: &Subject) -> Result<()> {
        let skey = subject.keys.last().ok_or("No active subject-key found!")?;
        let sig_data = Self::data(&self.sid, &self.authorized, &self.profiles);
        if !self.sig.verify(&skey.key, &sig_data) {
            return Err("Invalid consent signature!".into())
        }

        // check for existing profiles in the subject
        for item in self.profiles.iter() {
            if !subject.profiles.contains_key(item) {
                return Err(format!("No profile found: {}", item))
            }
        }

        Ok(())
    }

    fn data(sid: &str, authorized: &str, profiles: &[String]) -> [Vec<u8>; 3] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_sid = bincode::serialize(sid).unwrap();
        let b_authorized = bincode::serialize(authorized).unwrap();
        let b_profiles = bincode::serialize(profiles).unwrap();

        [b_sid, b_authorized, b_profiles]
    }
}

//-----------------------------------------------------------------------------------------------------------
// Revoked Consent
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RevokeConsent {
    pub sid: String,                                // Subject identification
    pub consent: String,                            // Identifies the consent by the encoded signature

    pub sig: IndSignature,                          // Signature from data-subject
    #[serde(skip)] _phantom: () // force use of constructor
}

impl ID for RevokeConsent {
    fn id(&self) -> String {
        self.sig.sig.encoded.clone()
    }
}

impl RevokeConsent {
    pub fn sign(sid: &str, consent: &str, sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let sig_data = Self::data(sid, consent);
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, &sig_data);
        
        Self { sid: sid.into(), consent: consent.into(), sig, _phantom: () }
    }

    pub fn check(&self, subject: &Subject) -> Result<()> {
        let skey = subject.keys.last().ok_or("No active subject-key found!")?;
        let sig_data = Self::data(&self.sid, &self.consent);
        if !self.sig.verify(&skey.key, &sig_data) {
            return Err("Invalid revoke signature!".into())
        }

        Ok(())
    }
    
    fn data(sid: &str, consent: &str) -> [Vec<u8>; 2] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_sid = bincode::serialize(sid).unwrap();
        let b_consent = bincode::serialize(consent).unwrap();

        [b_sid, b_consent]
    }
}