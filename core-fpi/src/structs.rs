use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::{ExtSignature, SubSignature};

//-----------------------------------------------------------------------------------------------------------
// Subject
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Subject {
    pub sid: String,                            // Subject ID - <F-ID>:<Name>
    pub sigs: Option<Vec<ExtSignature>>,        // Extended Schnorr's signatures for (sid). Used to evolve subject keys.

    pub profiles: Option<Vec<Profile>>
}

impl Subject {
    pub fn new<S: Into<String>>(sid: S, s: &Scalar, key: CompressedRistretto) -> Self {
        let sid: String = sid.into();

        let data = &[sid.as_bytes()];
        let sig = ExtSignature::sign(s, key, data);
        
        Self { sid: sid, sigs: Some(vec![sig]), profiles: None }
    }

    pub fn push(&mut self, profile: Profile) {
        let values = self.profiles.get_or_insert(Vec::new());
        values.push(profile);
    }
}

//-----------------------------------------------------------------------------------------------------------
// Profile
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Profile {
    pub pid: String,                            // Profile ID - <T-ID>:<UUID> where T-ID is a pre-defined profile type, ex: HealthCare, Financial, Assets, etc
    pub lurl: String,                           // Location URL (URL for the profile server)
    pub sig: Option<SubSignature>,              // Subject signature for (sid, pid, lurl)

    keys: Option<Vec<ProfileKey>>
}

impl Profile {
    pub fn new<S: Into<String>>(sid: S, pid: S, lurl: S, index: usize, s: &Scalar, key: &CompressedRistretto) -> Self {
        let sid: String = sid.into();
        let pid: String = pid.into();
        let lurl: String = lurl.into();

        let data = &[sid.as_bytes(), pid.as_bytes(), lurl.as_bytes()];
        let sig = SubSignature::sign(index, s, key, data);
        
        Self { pid: pid, lurl: lurl, sig: Some(sig), keys: None }
    }

    pub fn push(&mut self, pkey: ProfileKey) {
        let values = self.keys.get_or_insert(Vec::new());
        values.push(pkey);
    }
}

//-----------------------------------------------------------------------------------------------------------
// Profile PublicKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct ProfileKey {
    pub active: bool,                      // Is being in use?
    pub esig: ExtSignature,                // Extended Schnorr's signature for (active, sid, pid) to register the profile key
    pub sig: Option<SubSignature>,         // Subject signature for (active, sid, pid, esig)
}

impl ProfileKey {
    pub fn new<S: Into<String>>(active: bool, sid: S, pid: S, profile_s: &Scalar, profile_key: CompressedRistretto, index: usize, subject_s: &Scalar, subject_key: &CompressedRistretto) -> Self {
        let sid: String = sid.into();
        let pid: String = pid.into();

        let active_bytes = if active { &[1u8] } else { &[0u8] };

        let edata = &[active_bytes, sid.as_bytes(), pid.as_bytes()];
        let esig = ExtSignature::sign(profile_s, profile_key, edata);
        let esig_bytes = esig.to_bytes();

        let data = &[edata[0], edata[1], edata[2], &esig_bytes];
        let sig = SubSignature::sign(index, subject_s, subject_key, data);
        
        Self { active: active, esig: esig, sig: Some(sig) }
    }
}