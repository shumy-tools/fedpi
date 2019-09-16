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
    pub keys: Vec<SubjectKey>,                              // All subject keys

    pub profiles: Option<HashMap<String, Profile>>,
    _phantom: () // force use of constructor
}

impl Subject {
    pub fn new<S: Into<String>>(sid: S) -> Self {
        let sid: String = sid.into();
        Self { sid: sid, ..Default::default() }
    }

    pub fn active_key(&self) -> Option<&SubjectKey> {
        self.keys.last()
    }

    pub fn push_key(&mut self, skey: SubjectKey) {
        self.keys.push(skey);
    }

    pub fn find_profile(&self, typ: &str, lurl: &str) -> Option<&Profile> {
        let pid = Profile::pid(typ, lurl);
        let profiles = self.profiles.as_ref()?;
        profiles.get(&pid)
    }

    pub fn push_profile(&mut self, profile: Profile) -> &mut Self {
        let values = self.profiles.get_or_insert(HashMap::new());
        values.insert(profile.id(), profile);
        self
    }

    pub fn check(&self, current: Option<&Subject>) -> Result<(), &'static str> {
        match self.keys.len() {
            0 => {
                let current = current.ok_or("Subject update must have a current subject!")?;
                self.check_update(current)
            }, 
            1 => {
                match current {
                    None => self.check_create(),
                    Some(current) => self.check_evolve(current)
                }
            }, 
            _ => Err("Incorrect number of keys for subject sync!")
        }
    }

    fn check_create(&self) -> Result<(), &'static str> {
        // TODO: check "sid" string format

        // if it reaches here it must have one key with index 0
        let active_key = self.keys.last().ok_or("No key found for subject creation!")?;
        if active_key.sig.index != 0 {
            return Err("Incorrect key index for subject creation!")
        }

        // a self-signed SubjectKey
        active_key.check(&self.sid, active_key)?;

        // check profiles (it's ok if there are no profiles)
        if let Some(profiles) = &self.profiles {
            let empty_map = HashMap::<String, Profile>::new();
            return Subject::check_profiles(&self.sid, &profiles, &empty_map, active_key)
        }

        Ok(())
    }

    fn check_evolve(&self, current: &Subject) -> Result<(), &'static str>  {
        // check the key
        let active_key = current.keys.last().ok_or("Current subject must have an active key!")?;
        let new_key = self.keys.last().ok_or("No subject-key at expected index!")?;

        if active_key.sig.index + 1 != new_key.sig.index {
            return Err("Incorrect index for new subject-key!")
        }

        new_key.check(&self.sid, active_key)?;

        if self.profiles.is_some() {
            return Err("Subject key-evolution cannot have profiles!")
        }

        Ok(())
    }

    fn check_update(&self, current: &Subject) -> Result<(), &'static str> {
        if self.sid != current.sid {
            // if it executes it's a bug in the code
            return Err("self.sid != update.sid")
        }

        // get active key for subject
        let active_key = current.keys.last().ok_or("Current subject must have an active key!")?;

        // check profiles
        let profiles = self.profiles.as_ref().ok_or("Subject update must have profiles!")?;
        if profiles.len() == 0 {
            return Err("Subject update must have at least one profile!")
        }

        let current_profiles = current.profiles.as_ref().ok_or("Current subject must expose profiles!")?;
        Subject::check_profiles(&self.sid, &profiles, &current_profiles, active_key)
    }

    fn check_profiles(sid: &str, profiles: &HashMap<String, Profile>, current: &HashMap<String, Profile>, active_key: &SubjectKey) -> Result<(), &'static str> {
        for (key, item) in profiles.iter() {
            if *key != item.id() {
                return Err("Incorrect profile map-key!")
            }

            item.check(sid, current.get(key), active_key)?;
        }

        Ok(())
    }
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
    pub fn new(sid: &str, index: usize, skey: CompressedRistretto, sig_s: &Scalar, sig_key: &CompressedRistretto) -> Self {
        let index_bytes = index.to_be_bytes();

        let data = &[sid.as_bytes(), &index_bytes, skey.as_bytes()];
        let sig = IndSignature::sign(index, sig_s, sig_key, data);
        
        Self { key: skey, sig: sig }
    }

    pub fn evolve(&self, sid: &str, skey: CompressedRistretto, sig_s: &Scalar) -> Self {
        SubjectKey::new(sid, self.sig.index + 1, skey, sig_s, &self.key)
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
#[derive(Debug, Default)]
pub struct Profile {
    pub typ: String,                            // Profile Type ex: HealthCare, Financial, Assets, etc
    pub lurl: String,                           // Location URL (URL for the profile server)
    sig: Option<IndSignature>,                  // Subject signature for (typ, lurl)

    pub keys: HashMap<String, ProfileKey>
}

impl Profile {
    pub fn id(&self) -> String {
        Profile::pid(&self.typ, &self.lurl)
    }

    pub fn pid(typ: &str, lurl: &str) -> String {
        format!("{}@{}", typ, lurl).to_string()
    }

    pub fn new(typ: &str, lurl: &str) -> Self {
        Self { typ: typ.into(), lurl: lurl.into(), ..Default::default() }
    }

    pub fn sign(&mut self, sid: &str, sig_s: &Scalar, sig_key: &SubjectKey) {
        let data = &[sid.as_bytes(), self.typ.as_bytes(), self.lurl.as_bytes()];
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, data);

        self.sig = Some(sig);
    }

    pub fn push_key(&mut self, pkey: ProfileKey) -> &mut Self {
        self.keys.insert(pkey.id(), pkey);
        self
    }

    #[allow(non_snake_case)]
    pub fn new_profile_key(&mut self, sid: &str, sig_s: &Scalar, sig_key: &SubjectKey) -> Scalar {
        use crate::{G, rnd_scalar};

        let secret = rnd_scalar();
        let P = (secret * G).compress();

        let pkey = ProfileKey::new(true, sid, &self.typ, &self.lurl, &secret, P, sig_s, sig_key);
        self.keys.insert(pkey.id(), pkey);
        
        secret
    }

    fn check(&self, sid: &str, current: Option<&Profile>, active_key: &SubjectKey) -> Result<(), &'static str> {
        // check profile
        match &self.sig {
            None => {
                if current.is_none() {
                    return Err("Profile cannot be updated, it doesn't exist!"); 
                }
            },
            Some(sig) => {
                if current.is_some() {
                    return Err("Profile cannot be created, already exist!")
                }

                // TODO: check "typ" and "lurl" fields?

                // check signature
                let data = &[sid.as_bytes(), self.typ.as_bytes(), self.lurl.as_bytes()];
                if !sig.verify(&active_key.key, data) {
                    return Err("Invalid profile signature!")
                }
            }
        }

        // check profile keys
        if self.keys.is_empty() {
            return Err("Profile must have keys!")
        }

        for (key, item) in self.keys.iter() {
            if *key != item.id() {
                return Err("Incorrect profile map-key!")
            }

            // key already exists?
            if current.is_none() || current.unwrap().keys.get(key).is_none() {
                if !item.active {
                    return Err("New profile-key must be active!")
                }
            } else if item.active {
                return Err("Existing profile-key can only be disabled!")
            }

            item.check(sid, &self.typ, &self.lurl, active_key)?;
        }

        Ok(())
    }
}

//-----------------------------------------------------------------------------------------------------------
// ProfileKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct ProfileKey {
    pub active: bool,                       // Is being used?
    pub esig: ExtSignature,                 // Extended Schnorr's signature for (active, sid, pid) to register the profile key
    sig: IndSignature,                      // Subject signature for (active, sid, typ, lurl, esig)
}

impl ProfileKey {
    pub fn id(&self) -> String {
        self.esig.key.encode()
    }

    pub fn new(active: bool, sid: &str, typ: &str, lurl: &str, profile_s: &Scalar, profile_key: CompressedRistretto, sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let active_bytes = if active { &[1u8] } else { &[0u8] };

        let edata = &[active_bytes, sid.as_bytes(), typ.as_bytes(), lurl.as_bytes()];
        let esig = ExtSignature::sign(profile_s, profile_key, edata);

        let esig_bytes = esig.to_bytes();
        let data = &[edata[0], edata[1], edata[2], edata[3], &esig_bytes];
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, data);
        
        Self { active: active, esig: esig, sig: sig }
    }

    pub fn check(&self, sid: &str, typ: &str, lurl: &str, active_key: &SubjectKey) -> Result<(), &'static str> {
        let active_bytes = if self.active { &[1u8] } else { &[0u8] };
        let edata = &[active_bytes, sid.as_bytes(), typ.as_bytes(), lurl.as_bytes()];
        if !self.esig.verify(edata) {
            return Err("Invalid profile-key ext-signature!")
        }

        let esig_bytes = self.esig.to_bytes();
        let data = &[edata[0], edata[1], edata[2], edata[3], &esig_bytes];
        if !self.sig.verify(&active_key.key, data) {
            return Err("Invalid profile-key signature!")
        }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{G, rnd_scalar};

    #[allow(non_snake_case)]
    #[test]
    fn test_correct_construction() {
        //--------------------------------------------------
        // Creating Subject
        // -------------------------------------------------
        let sig_s1 = rnd_scalar();
        let sig_key1 = (sig_s1 * G).compress();
        
        let sid = "s-id:shumy";
        let skey1 = SubjectKey::new(sid, 0, sig_key1, &sig_s1, &sig_key1);
        
        let mut p1 = Profile::new("Assets", "https://profile-url.org");
        p1.sign(sid, &sig_s1, &skey1);
        p1.new_profile_key(sid, &sig_s1, &skey1);

        let mut p2 = Profile::new("Finance", "https://profile-url.org");
        p2.sign(sid, &sig_s1, &skey1);
        p2.new_profile_key(sid, &sig_s1, &skey1);

        let mut new1 = Subject::new(sid);
        new1
            .push_profile(p1)
            .push_profile(p2)
            .push_key(skey1);
        assert!(new1.check(None) == Ok(()));

        //--------------------------------------------------
        // Evolving SubjectKey
        // -------------------------------------------------
        let sig_key2 = (rnd_scalar() * G).compress();
        let skey2 = new1.active_key().unwrap().evolve(sid, sig_key2, &sig_s1);

        let mut update1 = Subject::new(sid);
        update1.push_key(skey2);
        assert!(update1.check(Some(&new1)) == Ok(()));

        //--------------------------------------------------
        // Updating Profile
        // -------------------------------------------------
        let mut p3 = Profile::new("HealthCare", "https://profile-url.org");
        p3.sign(sid, &sig_s1, &new1.active_key().unwrap());
        p3.new_profile_key(sid, &sig_s1, &new1.active_key().unwrap());

        let mut update2 = Subject::new(sid);
        update2.push_profile(p3);
        assert!(update2.check(Some(&new1)) == Ok(()));

        //--------------------------------------------------
        // Updating ProfileKey
        // -------------------------------------------------
        let mut empty_p2 = Profile::new("Finance", "https://profile-url.org");
        empty_p2.new_profile_key(sid, &sig_s1, &new1.active_key().unwrap());

        let mut update3 = Subject::new(sid);
        update3.push_profile(empty_p2);
        assert!(update3.check(Some(&new1)) == Ok(()));
        
        // println!("ERROR: {:?}", subject3.check(Some(&subject1)));
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_incorrect_construction() {
        let sig_s1 = rnd_scalar();
        let sig_key1 = (sig_s1 * G).compress();
        let sid = "s-id:shumy";

        let skey1 = SubjectKey::new(sid, 0, sig_key1, &sig_s1, &sig_key1);
        
        let mut p1 = Profile::new("Assets", "https://profile-url.org");
        p1.sign(sid, &sig_s1, &skey1);
        let s1 = p1.new_profile_key(sid, &sig_s1, &skey1);

        let mut new1 = Subject::new(sid);
        new1
            .push_profile(p1)
            .push_key(skey1);
        assert!(new1.check(None) == Ok(()));

        //--------------------------------------------------
        // Creating Subject
        // -------------------------------------------------
        let incorrect = Subject::new(sid);
        assert!(incorrect.check(None) == Err("Subject update must have a current subject!"));

        let mut incorrect = Subject::new(sid);
        let skey1 = SubjectKey::new(sid, 1, sig_key1, &sig_s1, &sig_key1);

        incorrect.push_key(skey1);
        assert!(incorrect.check(None) == Err("Incorrect key index for subject creation!"));

        //--------------------------------------------------
        // Evolving SubjectKey
        // -------------------------------------------------
        let sig_s2 = rnd_scalar();
        let sig_key2 = (sig_s2 * G).compress();

        // try to evolve with wrong index and self-signed!
        let skey2 = SubjectKey::new(sid, 0, sig_key2, &sig_s1, &sig_key1);
        let skey3 = SubjectKey::new(sid, 1, sig_key2, &sig_s2, &sig_key2);

        let mut incorrect = Subject::new(sid);
        incorrect.push_key(skey2);
        assert!(incorrect.check(Some(&new1)) == Err("Incorrect index for new subject-key!"));

        let mut incorrect = Subject::new(sid);
        incorrect.push_key(skey3);
        assert!(incorrect.check(Some(&new1)) == Err("Invalid subject-key signature!"));

        //--------------------------------------------------
        // Updating Profile
        // -------------------------------------------------
        let mut p2 = Profile::new("Assets", "https://profile-url.org");
        p2.sign(sid, &sig_s1, &new1.active_key().unwrap());
        p2.new_profile_key(sid, &sig_s1, &new1.active_key().unwrap());

        let mut update1 = Subject::new(sid);
        update1.push_profile(p2);
        assert!(update1.check(Some(&new1)) == Err("Profile cannot be created, already exist!"));

        //--------------------------------------------------
        // Updating ProfileKey
        // -------------------------------------------------
        let mut empty_p2 = Profile::new("Assets", "https://profile-url.org");
        let p2_key = ProfileKey::new(true, sid, "Assets", "https://profile-url.org", &s1, (s1 * G).compress(), &sig_s1, &new1.active_key().unwrap());
        empty_p2.push_key(p2_key);

        let mut update2 = Subject::new(sid);
        update2.push_profile(empty_p2);
        assert!(update2.check(Some(&new1)) == Err("Existing profile-key can only be disabled!"));

    }
}