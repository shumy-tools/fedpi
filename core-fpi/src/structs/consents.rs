use std::fmt::{Debug, Formatter};
use serde::{Serialize, Deserialize};

use crate::crypto::signatures::{Signature, IndSignature};
use crate::ids::SubjectKey;
use crate::{Result, KeyEncoder, Scalar, RistrettoPoint};

//-----------------------------------------------------------------------------------------------------------
// Subject Consent
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct Consent {
    pub sid: String,                                // Subject identification
    pub profiles: Vec<String>,                      // List of consented profiles (full disclosure)
    pub authorized: RistrettoPoint,                 // Authorized client-key

    pub sig: IndSignature,                          // Signature from data-subject
    #[serde(skip)] _phantom: () // force use of constructor
}

impl Debug for Consent {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Consent")
            .field("sid", &self.sid)
            .field("profiles", &self.profiles)
            .field("authorized", &self.authorized.encode())
            .field("sig", &self.sig)
            .finish()
    }
}

impl Consent {
    pub fn sign(sid: &str, profiles: &[String], authorized: &RistrettoPoint, sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let sig_data = Self::data(sid, profiles, authorized);
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, &sig_data);
        
        Self { sid: sid.into(), profiles: profiles.to_vec(), authorized: *authorized, sig, _phantom: () }

    }

    pub fn check(&self, sig_key: &SubjectKey) -> Result<()> {
        let sig_data = Self::data(&self.sid, &self.profiles, &self.authorized);
        if !self.sig.verify(&sig_key.key, &sig_data) {
            return Err("Invalid consent signature!")
        }

        Ok(())
    }


    fn data(sid: &str, profiles: &[String], authorized: &RistrettoPoint) -> [Vec<u8>; 3] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_sid = bincode::serialize(sid).unwrap();
        let b_profiles = bincode::serialize(profiles).unwrap();
        let b_authorized = bincode::serialize(authorized).unwrap();

        [b_sid, b_profiles, b_authorized]
    }
}

//-----------------------------------------------------------------------------------------------------------
// Revoked Consent
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RevokeConsent {
    pub sid: String,                                // Subject identification
    pub authorized: RistrettoPoint,                 // Authorized client-key
    pub consent: Signature,                         // Identifies the consent by the signature

    pub sig: IndSignature,                          // Signature from data-subject
    #[serde(skip)] _phantom: () // force use of constructor
}

impl RevokeConsent {
    pub fn sign(sid: &str, authorized: &RistrettoPoint, consent: &Signature, sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let sig_data = Self::data(sid, authorized, consent);
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, &sig_data);
        
        Self { sid: sid.into(), authorized: *authorized, consent: consent.clone(), sig, _phantom: () }

    }

    pub fn check(&self, sig_key: &SubjectKey) -> Result<()> {
        let sig_data = Self::data(&self.sid, &self.authorized, &self.consent);
        if !self.sig.verify(&sig_key.key, &sig_data) {
            return Err("Invalid consent signature!")
        }

        Ok(())
    }
    
    fn data(sid: &str, authorized: &RistrettoPoint, consent: &Signature) -> [Vec<u8>; 3] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_sid = bincode::serialize(sid).unwrap();
        let b_authorized = bincode::serialize(authorized).unwrap();
        let b_consent = bincode::serialize(consent).unwrap();

        [b_sid, b_authorized, b_consent]
    }
}