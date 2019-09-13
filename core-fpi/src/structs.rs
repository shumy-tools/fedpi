use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::{ExtSignature, IndSignature};

//-----------------------------------------------------------------------------------------------------------
// Subject
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct Subject {
    pub sid: String,                            // Subject ID - <F-ID>:<Name>
    pub keys: Option<Vec<SubjectKey>>,          // All subject keys

    profiles: Option<Vec<Profile>>
}

impl Subject {
    pub fn new<S: Into<String>>(sid: S) -> Self {
        let sid: String = sid.into();
        Self { sid: sid, keys: None, profiles: None }
    }

    pub fn push_key(&mut self, key: SubjectKey) -> &mut Self {
        let values = self.keys.get_or_insert(Vec::new());
        values.push(key);
        self
    }

    pub fn push_profile(&mut self, profile: Profile) -> &mut Self {
        let values = self.profiles.get_or_insert(Vec::new());
        values.push(profile);
        self
    }

    pub fn active_key(&self) -> Result<&SubjectKey, &'static str> {
        let active_key = match &self.keys {
            None => return Err("Subject must have keys!"),
            Some(keys) => match keys.last() {
                None => return Err("Subject must have keys!"),
                Some(key) => key
            }
        };

        Ok(active_key)
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

                // if it reaches here it must have one key (unwrap will always work)
                let active_key = keys.last().unwrap();
                active_key.check(&self.sid, active_key)?; // a self-signed SubjectKey

                // check profiles
                self.check_profiles(active_key, self)
            }
        }
    }

    pub fn check_update(&self, current: &Subject) -> Result<(), &'static str> {
        if self.sid != current.sid {
            // is it executes it's a bug in the code
            return Err("self.sid != update.sid")
        }

        // get active key for subject
        let mut active_key = current.active_key()?;

        // check key evolutions
        if let Some(keys) = &self.keys {
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
        self.check_profiles(active_key, current)
    }

    fn check_profiles(&self, active_key: &SubjectKey, current: &Subject) -> Result<(), &'static str> {
        match &self.profiles {
            None => Ok(()),
            Some(profiles) => {
                // TODO: check for existing profiles?
                // get current profile from current Subject?

                for item in profiles.iter() {
                    item.check(&self.sid, active_key)?
                }

                Ok(())
            }
        }
    }
}

//-----------------------------------------------------------------------------------------------------------
// SubjectKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct SubjectKey {
    pub key: CompressedRistretto,               // The public key
    pub sig: IndSignature,                      // Signature from the previous key (if exists) for (sid, index, key)
}

impl SubjectKey {
    pub fn new<S: Into<String>>(sid: S, index: usize, key: CompressedRistretto, sig_s: &Scalar, sig_key: &CompressedRistretto) -> Self {
        let sid: String = sid.into();
        let index_bytes = index.to_be_bytes();

        let data = &[sid.as_bytes(), &index_bytes, key.as_bytes()];
        let sig = IndSignature::sign(index, sig_s, sig_key, data);
        
        Self { key: key, sig: sig }
    }

    fn check(&self, sid: &String, key: &SubjectKey) -> Result<(), &'static str> {
        let index = self.sig.index;
        let index_bytes = index.to_be_bytes();

        let data = &[sid.as_bytes(), &index_bytes, self.key.as_bytes()];
        if !self.sig.verify(&key.key, data) {
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
    pub pid: String,                            // Profile ID - <T-ID>:<UUID> where T-ID is a pre-defined profile type, ex: HealthCare, Financial, Assets, etc
    pub lurl: Option<String>,                   // Location URL (URL for the profile server)
    pub sig: Option<IndSignature>,              // Subject signature for (sid, pid, lurl)

    keys: Option<Vec<ProfileKey>>
}

impl Profile {
    pub fn new<S: Into<String>>(sid: S, pid: S, lurl: S, sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let sid: String = sid.into();
        let pid: String = pid.into();
        let lurl: String = lurl.into();

        let data = &[sid.as_bytes(), pid.as_bytes(), lurl.as_bytes()];
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, data);
        
        Self { pid: pid, lurl: Some(lurl), sig: Some(sig), keys: None }
    }

    pub fn push_key(&mut self, pkey: ProfileKey) -> &mut Self {
        let values = self.keys.get_or_insert(Vec::new());
        values.push(pkey);
        self
    }

    fn check(&self, sid: &String, key: &SubjectKey) -> Result<(), &'static str> {
        // check new profile
        if let Some(sig) = &self.sig {
            match &self.lurl {
                None => return Err("Profile must have a location url (lurl)!"),
                Some(lurl) => {
                    // TODO: check "pid" and "lurl" string format

                    // check signature
                    let data = &[sid.as_bytes(), self.pid.as_bytes(), lurl.as_bytes()];
                    if !sig.verify(&key.key, data) {
                        return Err("Invalid profile signature!")
                    }
                }
            }
        }

        // check profile keys
        match &self.keys {
            None => Ok(()),
            Some(keys) => {
                for item in keys.iter() {
                    // TODO: check for existing keys?

                    item.check(sid, &self.pid, key)?
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
    pub sig: Option<IndSignature>,         // Subject signature for (active, sid, pid, esig)
}

impl ProfileKey {
    pub fn new<S: Into<String>>(active: bool, sid: S, pid: S, profile_s: &Scalar, profile_key: CompressedRistretto, sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let sid: String = sid.into();
        let pid: String = pid.into();

        let active_bytes = if active { &[1u8] } else { &[0u8] };

        let edata = &[active_bytes, sid.as_bytes(), pid.as_bytes()];
        let esig = ExtSignature::sign(profile_s, profile_key, edata);

        let esig_bytes = esig.to_bytes();
        let data = &[edata[0], edata[1], edata[2], &esig_bytes];
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, data);
        
        Self { active: active, esig: esig, sig: Some(sig) }
    }

    pub fn check(&self, sid: &String, pid: &String, key: &SubjectKey) -> Result<(), &'static str> {
        // check new profile key
        if let Some(sig) = &self.sig {
            //check signatures
            let active_bytes = if self.active { &[1u8] } else { &[0u8] };
            let edata = &[active_bytes, sid.as_bytes(), pid.as_bytes()];
            if !self.esig.verify(edata) {
                return Err("Invalid profile-key ext-signature!")
            }

            let esig_bytes = self.esig.to_bytes();
            let data = &[edata[0], edata[1], edata[2], &esig_bytes];
            if !sig.verify(&key.key, data) {
                return Err("Invalid profile-key signature!")
            }
        }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{G, uuid, rnd_scalar};

    #[allow(non_snake_case)]
    #[test]
    fn test_correct_construction() {
        let s = rnd_scalar();
        let Ps = (s * G).compress();
        
        let sid = "s-id:shumy";
        let key = SubjectKey::new(sid, 0, Ps, &s, &Ps);
        let p1 = Profile::new(sid, format!("Assets:{}", uuid()).as_str(), "https://profile-url.org", &s, &key);
        let p2 = Profile::new(sid, format!("Assets:{}", uuid()).as_str(), "https://profile-url.org", &s, &key);

        let mut subject = Subject::new(sid);
        subject
            .push_profile(p1)
            .push_profile(p2)
            .push_key(key);

        assert!(subject.check_create() == Ok(()))
    }
}