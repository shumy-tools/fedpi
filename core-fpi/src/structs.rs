use std::collections::HashMap;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::{KeyEncoder, ExtSignature, IndSignature};

//-----------------------------------------------------------------------------------------------------------
// Subject
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Default)]
pub struct Subject {
    pub sid: String,                                        // Subject ID - <F-ID>:<Name>
    pub keys: Option<HashMap<usize, SubjectKey>>,           // All subject keys
    active: usize,

    pub profiles: Option<HashMap<String, Profile>>,
}

impl Subject {
    pub fn new<S: Into<String>>(sid: S) -> Self {
        let sid: String = sid.into();
        Self { sid: sid, ..Default::default() }
    }

    pub fn evolve(&mut self, key: SubjectKey) -> &mut Self {
        self.active = key.sig.index;
        let values = self.keys.get_or_insert(HashMap::new());
        values.insert(key.sig.index, key);

        self
    }

    pub fn push(&mut self, profile: Profile) -> &mut Self {
        let values = self.profiles.get_or_insert(HashMap::new());
        values.insert(format!("{}@{}", profile.typ, profile.lurl), profile);
        self
    }

    pub fn active_key(&self) -> Result<&SubjectKey, &'static str> {
        match &self.keys {
            None => Err("Subject must have keys!"),
            Some(keys) => match keys.get(&self.active) {
                None => Err("Incorrect active key index!"),
                Some(key) => Ok(key)
            }
        }
    }

    pub fn check_create(&self) -> Result<(), &'static str> {
        // TODO: check "sid" string format

        // check key
        match &self.keys {
            None => return Err("Subject must have keys!"),
            Some(keys) => {
                if keys.len() != 1 {
                    return Err("Incorrect number of keys for subject creation!")
                }

                // if it reaches here it must have one key with index 0
                let active_key = match keys.get(&0) {
                    None => return Err("Incorrect key index for subject creation!"),
                    Some(key) => {
                        if key.sig.index != 0 {
                            return Err("Incorrect key index for subject creation!")
                        }

                        // a self-signed SubjectKey
                        key.check(&self.sid, key)?;
                        key
                    }
                };

                // check profiles
                match &self.profiles {
                    None => Ok(()),
                    Some(profiles) => {
                        for (key, item) in profiles.iter() {
                            if *key != format!("{}@{}", item.typ, item.lurl).to_string() {
                                return Err("Incorrect subject map-key!")
                            }

                            item.check_create(&self.sid, active_key)?
                        }

                        Ok(())
                    }
                }
            }
        }
    }

    /*pub fn check_update(&self, current: &Subject) -> Result<(), &'static str> {
        if self.sid != current.sid {
            // is it executes it's a bug in the code
            return Err("self.sid != update.sid")
        }

        // get active key for subject
        let mut active_key = current.active_key()?;

        // check key evolutions
        if let Some(keys) = &current.keys {
            if keys.len() != 1 {
                return Err("Incorrect number of keys for key-evolution!")
            }

            // if it reaches here it must have one key (unwrap will always work)
            let new_key = keys.last().unwrap();
            if active_key.sig.index + 1 != new_key.sig.index {
                return Err("Invalid subject-key sequence!")
            }

            new_key.check(&self.sid, active_key)?;
            active_key = new_key;
        }

        // check profiles
        match self.profiles {
            None => Ok(()),
            Some(profiles) => {
                // TODO: check for existing profiles? (existing pid or existing (type, lurl))
                // get current profile from current Subject?

                for item in profiles.iter() {
                    item.check_update(&self.sid, active_key)?
                }

                Ok(())
            }
        }
    }*/
}

//-----------------------------------------------------------------------------------------------------------
// SubjectKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct SubjectKey {
    pub key: CompressedRistretto,               // The public key
    sig: IndSignature,                          // Signature from the previous key (if exists) for (sid, index, key)
}

impl SubjectKey {
    pub fn new(sid: &str, index: usize, key: CompressedRistretto, sig_s: &Scalar, sig_key: &CompressedRistretto) -> Self {
        let index_bytes = index.to_be_bytes();

        let data = &[sid.as_bytes(), &index_bytes, key.as_bytes()];
        let sig = IndSignature::sign(index, sig_s, sig_key, data);
        
        Self { key: key, sig: sig }
    }

    fn check(&self, sid: &str, sig_key: &SubjectKey) -> Result<(), &'static str> {
        let index = self.sig.index;
        let index_bytes = index.to_be_bytes();

        let data = &[sid.as_bytes(), &index_bytes, self.key.as_bytes()];
        if !self.sig.verify(&sig_key.key, data) {
            return Err("Invalid subject-key signature!")
        }

        Ok(())
    }
}

//-----------------------------------------------------------------------------------------------------------
// Profile
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Profile {
    pub typ: String,                            // Profile Type ex: HealthCare, Financial, Assets, etc
    pub lurl: String,                           // Location URL (URL for the profile server)
    sig: Option<IndSignature>,                  // Subject signature for (typ, lurl)

    pub keys: Option<HashMap<String, ProfileKey>>
}

impl Profile {
    pub fn new(sid: &str, typ: &str, lurl: &str, sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let data = &[sid.as_bytes(), typ.as_bytes(), lurl.as_bytes()];
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, data);
        
        Self { typ: typ.into(), lurl: lurl.into(), sig: Some(sig), keys: None }
    }

    pub fn push(&mut self, pkey: ProfileKey) -> &mut Self {
        let values = self.keys.get_or_insert(HashMap::new());
        values.insert(pkey.esig.key.encode(), pkey);
        self
    }

    fn check_create(&self, sid: &str, active_key: &SubjectKey) -> Result<(), &'static str> {
        // TODO: check "typ" and "lurl" string format

        // check new profile
        match &self.sig {
            None => return Err("Profile creation must have a signature!"),
            Some(sig) => {
                // check signature
                let data = &[sid.as_bytes(), self.typ.as_bytes(), self.lurl.as_bytes()];
                if !sig.verify(&active_key.key, data) {
                    return Err("Invalid profile signature!")
                }
            }
        }

        // check profile keys
        match &self.keys {
            None => return Err("Profile creation must have a key!"),
            Some(keys) => {
                for (key, item) in keys.iter() {
                    if *key != item.esig.key.encode() {
                        return Err("Incorrect profile map-key!")
                    }

                    if !item.active {
                        return Err("New profile-keys must be active!")
                    }

                    item.check(sid, &self.typ, &self.lurl, active_key)?
                }

                Ok(())
            }
        }
    }
}

//-----------------------------------------------------------------------------------------------------------
// ProfileKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct ProfileKey {
    pub active: bool,                      // Is being used?
    pub esig: ExtSignature,                // Extended Schnorr's signature for (active, sid, pid) to register the profile key
    sig: Option<IndSignature>,             // Subject signature for (active, sid, typ, lurl, esig)
}

impl ProfileKey {
    pub fn new(active: bool, sid: &str, typ: &str, lurl: &str, profile_s: &Scalar, profile_key: CompressedRistretto, sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let active_bytes = if active { &[1u8] } else { &[0u8] };

        let edata = &[active_bytes, sid.as_bytes(), typ.as_bytes(), lurl.as_bytes()];
        let esig = ExtSignature::sign(profile_s, profile_key, edata);

        let esig_bytes = esig.to_bytes();
        let data = &[edata[0], edata[1], edata[2], edata[3], &esig_bytes];
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, data);
        
        Self { active: active, esig: esig, sig: Some(sig) }
    }

    pub fn check(&self, sid: &str, typ: &str, lurl: &str, active_key: &SubjectKey) -> Result<(), &'static str> {
        // check new profile-key
        match &self.sig {
            None => Err("ProfileKey creation must have a signature!"),
            Some(sig) => {
                //check signatures
                let active_bytes = if self.active { &[1u8] } else { &[0u8] };
                let edata = &[active_bytes, sid.as_bytes(), typ.as_bytes(), lurl.as_bytes()];
                if !self.esig.verify(edata) {
                    return Err("Invalid profile-key ext-signature!")
                }

                let esig_bytes = self.esig.to_bytes();
                let data = &[edata[0], edata[1], edata[2], edata[3], &esig_bytes];
                if !sig.verify(&active_key.key, data) {
                    return Err("Invalid profile-key signature!")
                }

                Ok(())
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{G, rnd_scalar};

    #[allow(non_snake_case)]
    #[test]
    fn test_correct_construction() {
        let s = rnd_scalar();
        let Ps = (s * G).compress();
        
        let sid = "s-id:shumy";
        let key = SubjectKey::new(sid, 0, Ps, &s, &Ps);
        
        let s1 = rnd_scalar();
        let P1 = (s1 * G).compress();
        let mut p1 = Profile::new(sid, "Assets", "https://profile-url.org", &s, &key);
        p1.push(ProfileKey::new(true, sid, "Assets", "https://profile-url.org", &s1, P1, &s, &key));

        let s2 = rnd_scalar();
        let P2 = (s2 * G).compress();
        let mut p2 = Profile::new(sid, "Finance", "https://profile-url.org", &s, &key);
        p2.push(ProfileKey::new(true, sid, "Finance", "https://profile-url.org", &s2, P2, &s, &key));

        let mut subject = Subject::new(sid);
        subject
            .push(p1)
            .push(p2)
            .evolve(key);
        
        assert!(subject.check_create() == Ok(()))
    }
}