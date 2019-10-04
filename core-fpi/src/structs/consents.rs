use serde::{Serialize, Deserialize};

use crate::ids::*;
use crate::crypto::signatures::IndSignature;
use crate::{Result, ID, Scalar};

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum ConsentType {
    Consent, Revoke
}

//-----------------------------------------------------------------------------------------------------------
// Subject Consent/Revoke
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Consent {
    pub sid: String,                                // Subject-id submitting consent
    pub typ: ConsentType,                           // Consent or revoke
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
    pub fn sign(sid: &str, typ: ConsentType, authorized: &str, profiles: &[String], sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let sig_data = Self::data(sid, &typ, authorized, profiles);
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, &sig_data);
        
        Self { sid: sid.into(), typ, authorized: authorized.into(), profiles: profiles.to_vec(), sig, _phantom: () }
    }

    pub fn check(&self, subject: &Subject) -> Result<()> {
        let skey = subject.keys.last().ok_or("No active subject-key found!")?;
        let sig_data = Self::data(&self.sid, &self.typ, &self.authorized, &self.profiles);
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

    fn data(sid: &str, typ: &ConsentType, authorized: &str, profiles: &[String]) -> [Vec<u8>; 4] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_sid = bincode::serialize(sid).unwrap();
        let b_typ = bincode::serialize(typ).unwrap();
        let b_authorized = bincode::serialize(authorized).unwrap();
        let b_profiles = bincode::serialize(profiles).unwrap();

        [b_sid, b_typ, b_authorized, b_profiles]
    }
}