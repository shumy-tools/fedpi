use std::cell::RefCell;
use std::collections::HashMap;

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

    profiles: RefCell<HashMap<String, Profile>>
}

impl Subject {
    constructors!(sid; profiles);

    pub fn contains(&self, pid: &String) -> bool {
        self.profiles.borrow().contains_key(pid)
    }

    pub fn add(&self, profile: Profile) {
        if self.sid != profile.sid {
            panic!("Profile not part of the Subject!");
        }

        let replaced = self.profiles.borrow_mut().insert(profile.pid.clone(), profile);
        if let Some(_) = replaced {
            panic!("Trying to replace an existing profile!");
        }
    }
}

//-----------------------------------------------------------------------------------------------------------
// Profile
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Profile {
    pub sid: String,                    // Reference to Subject ID
    pub pid: String,                    // Profile ID - <T-ID>:<UUID> where T-ID is a pre-defined profile type, ex: HealthCare, Financial, Assets, etc
    pub lurl: String,                   // Location URL (URL for the profile server)
    pub esig: ExtSignature,             // Extended Schnorr's signature for (pid, lurl)

    keys: RefCell<HashMap<String, ProfileKey>>
}

impl Profile {
    constructors!(sid, pid, lurl; keys);

    pub fn contains(&self, key: &String) -> bool {
        self.keys.borrow().contains_key(key)
    }

    pub fn add(&self, pkey: ProfileKey) {
        if self.sid != pkey.sid || self.pid != pkey.pid {
            panic!("ProfileKey not part of the Profile!");
        }

        let replaced = self.keys.borrow_mut().insert(pkey.key.clone(), pkey);
        if let Some(_) = replaced {
            panic!("Trying to replace an existing profile key!");
        }
    }
}

//-----------------------------------------------------------------------------------------------------------
// Profile PublicKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct ProfileKey {
    pub sid: String,                    // Reference to Subject ID
    pub pid: String,                    // Reference to Profile ID
    pub key: String,                    // Base58 encoded CompressedRistretto
    pub esig: ExtSignature,             // Extended Schnorr's signature for (pid)
}

impl ProfileKey {
    constructors!(sid, pid, key);
}