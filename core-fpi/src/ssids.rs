use std::cell::RefCell;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::ExtSignature;

//-----------------------------------------------------------------------------------------------------------
// Subject
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Subject {
    pub sid: String,                    // Subject ID - <F-ID>:<Name>
    pub esig: ExtSignature,             // Extended Schnorr's signature for (sid)

    profiles: RefCell<Vec<Profile>>
}

impl Subject {
    loaders!(sid; profiles);
}

//-----------------------------------------------------------------------------------------------------------
// Profile
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Profile {
    pub pid: String,                    // Profile ID - <T-ID>:<UUID> where T-ID is a pre-defined profile type, ex: HealthCare, Financial, Assets, etc
    pub lurl: String,                   // Location URL (URL for the profile server)
    pub esig: ExtSignature,             // Extended Schnorr's signature for (pid, lurl)

    keys: RefCell<Vec<ProfileKey>>
}

impl Profile {
    loaders!(pid, lurl; keys);
}

//-----------------------------------------------------------------------------------------------------------
// Profile PublicKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct ProfileKey {
    pub pid: String,                    // Reference to Profile ID
    pub esig: ExtSignature,             // Extended Schnorr's signature for (pid)
}

impl ProfileKey {
    loaders!(pid);
}