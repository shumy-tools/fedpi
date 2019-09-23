use std::fmt::{Debug, Formatter};
use std::collections::HashMap;

use serde::{Serialize, Deserialize};

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use crate::crypto::signatures::IndSignature;
use crate::{G, rnd_scalar, Result, KeyEncoder};

//-----------------------------------------------------------------------------------------------------------
// Subject
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Subject {
    pub sid: String,                                        // Subject ID - <F-ID>:<Name>
    pub keys: Vec<SubjectKey>,                              // All subject keys

    pub profiles: HashMap<String, Profile>,
    #[serde(skip)] _phantom: () // force use of constructor
}

impl Debug for Subject {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Subject")
            .field("sid", &self.sid)
            .field("keys", &self.keys)
            .field("profiles", &self.profiles)
            .finish()
    }
}

impl Subject {
    pub fn new(sid: &str) -> Self {
        Self { sid: sid.into(), ..Default::default() }
    }

    pub fn evolve(&self, sig_s: Scalar) -> (Scalar, SubjectKey) {
        let sig_key = (sig_s * G).compress();
        match self.keys.last() {
            None => (sig_s, SubjectKey::new(&self.sid, 0, sig_key, &sig_s, &sig_key)),
            Some(active) => {
                let secret = rnd_scalar();
                let skey = (secret * G).compress();
                (secret, SubjectKey::new(&self.sid, active.sig.index + 1, skey, &sig_s, &sig_key))
            }
        }
    }

    pub fn find(&self, typ: &str, lurl: &str) -> Option<&Profile> {
        let pid = Profile::pid(typ, lurl);
        self.profiles.get(&pid)
    }

    pub fn push(&mut self, profile: Profile) -> &mut Self {
        self.profiles.insert(profile.id(), profile);
        self
    }

    pub fn merge(&mut self, update: Subject) {
        self.keys.extend_from_slice(&update.keys);

        for (key, item) in update.profiles.into_iter() {
            match self.profiles.get_mut(&key) {
                None => {self.profiles.insert(key, item); ()},
                Some(ref mut current) => current.merge(item)
            }
        }
    }

    pub fn check(&self, current: Option<&Subject>) -> Result<()> {
        match current {
            None => self.check_create(),
            Some(current) => {
                match self.keys.len() {
                    0 => self.check_update(current),
                    1 => self.check_evolve(current),
                    _ => Err("Incorrect number of keys for subject sync!")
                }
            }
        }
    }

    // TODO: should be replaced by check_full with proper changes (verify key chain and select correct SubjectKey for profile)
    fn check_create(&self) -> Result<()> {
        // TODO: check "sid" string format

        // if it reaches here it must have one key with index 0
        let active_key = self.keys.last().ok_or("No key found for subject creation!")?;
        if active_key.sig.index != 0 {
            return Err("Incorrect key index for subject creation!")
        }

        // a self-signed SubjectKey
        active_key.check(&self.sid, active_key)?;

        // check profiles (it's ok if there are no profiles)
        let empty_map = HashMap::<String, Profile>::new();
        return Subject::check_profiles(&self.sid, &self.profiles, &empty_map, active_key)
    }

    fn check_evolve(&self, current: &Subject) -> Result<()>  {
        // check the key
        let active_key = current.keys.last().ok_or("Current subject must have an active key!")?;
        let new_key = self.keys.last().ok_or("No subject-key at expected index!")?;

        if active_key.sig.index + 1 != new_key.sig.index {
            return Err("Incorrect index for new subject-key!")
        }

        new_key.check(&self.sid, active_key)?;

        if !self.profiles.is_empty() {
            return Err("Subject key-evolution cannot have profiles!")
        }

        Ok(())
    }

    fn check_update(&self, current: &Subject) -> Result<()> {
        if self.sid != current.sid {
            // if it executes it's a bug in the code
            return Err("self.sid != update.sid")
        }

        // get active key for subject
        let active_key = current.keys.last().ok_or("Current subject must have an active key!")?;

        // check profiles
        if self.profiles.len() == 0 {
            return Err("Subject update must have at least one profile!")
        }

        Subject::check_profiles(&self.sid, &self.profiles, &current.profiles, active_key)
    }

    fn check_profiles(sid: &str, profiles: &HashMap<String, Profile>, current: &HashMap<String, Profile>, sig_key: &SubjectKey) -> Result<()> {
        for (key, item) in profiles.iter() {
            if *key != item.id() {
                return Err("Incorrect profile map-key!")
            }

            item.check(sid, current.get(key), sig_key)?;
        }

        Ok(())
    }
}

//-----------------------------------------------------------------------------------------------------------
// SubjectKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct SubjectKey {
    pub key: CompressedRistretto,                   // The public key
    pub sig: IndSignature,                          // Signature from the previous key (if exists) for (sid, index, key)
    #[serde(skip)] _phantom: () // force use of constructor
}

impl Debug for SubjectKey {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("SubjectKey")
            .field("key", &self.key.encode())
            .field("sig", &self.sig)
            .finish()
    }
}

impl SubjectKey {
    pub fn new(sid: &str, index: usize, skey: CompressedRistretto, sig_s: &Scalar, sig_key: &CompressedRistretto) -> Self {
        let data = &[sid.as_bytes(), &index.to_be_bytes(), skey.as_bytes()];
        let sig = IndSignature::sign(index, sig_s, sig_key, data);
        
        Self { key: skey, sig: sig, _phantom: () }
    }

    fn check(&self, sid: &str, sig_key: &SubjectKey) -> Result<()> {
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
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Profile {
    pub typ: String,                            // Profile Type ex: HealthCare, Financial, Assets, etc
    pub lurl: String,                           // Location URL (URL for the profile server)
    #[serde(skip)] _phantom: (), // force use of constructor
    
    // TODO: how to manage replicas without using identity keys?
    pub chain: Vec<ProfileKey>
}

impl Debug for Profile {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Profile")
            .field("typ", &self.typ)
            .field("lurl", &self.lurl)
            .finish()
    }
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

    pub fn evolve(&self, sid: &str, sig_s: &Scalar, sig_key: &SubjectKey) -> (Scalar, ProfileKey) {
        let secret = rnd_scalar();
        let key = (secret * G).compress();

        let pkey = match self.chain.last() {
            None => ProfileKey::new(sid, &self.typ, &self.lurl, 0, key, sig_s, sig_key),
            Some(active) => ProfileKey::new(sid, &self.typ, &self.lurl, active.index + 1, key, sig_s, sig_key)
        };

        (secret, pkey)
    }

    fn merge(&mut self, update: Profile) {
        self.chain.extend(update.chain);
    }

    fn check(&self, sid: &str, current: Option<&Profile>, sig_key: &SubjectKey) -> Result<()> {
        // check profile
        let mut prev = match current {
            None => {
                // TODO: check "typ" and "lurl" fields?
                -1
            },
            Some(current) => {
                let pkey = current.chain.last().ok_or("Current profile must have keys!")?;
                pkey.index as i32
            }
        };

        // check profile keys
        if self.chain.is_empty() {
            return Err("Profile must have keys!")
        }

        for item in self.chain.iter() {
            if prev + 1 != item.index as i32 {
                return Err("ProfileKey is not correcly chained!")
            }

            item.check(sid, &self.typ, &self.lurl, sig_key)?;
            prev = item.index as i32;
        }

        Ok(())
    }
}

//-----------------------------------------------------------------------------------------------------------
// ProfileKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct ProfileKey {
    pub index: usize,                       // Profile key index on the vector
    pub key: CompressedRistretto,           // The profile public key
    pub sig: IndSignature,                  // Subject signature for (sid, typ, lurl, index, key)
    #[serde(skip)] _phantom: () // force use of constructor
}

impl Debug for ProfileKey {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("ProfileKey")
            .field("index", &self.index)
            .field("key", &self.key.encode())
            .field("sig", &self.sig)
            .finish()
    }
}

impl ProfileKey {
    pub fn new(sid: &str, typ: &str, lurl: &str, index: usize, skey: CompressedRistretto, sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let data = &[sid.as_bytes(), typ.as_bytes(), lurl.as_bytes(), &index.to_be_bytes(), skey.as_bytes()];
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, data);
        
        Self { index: index, key: skey, sig: sig, _phantom: () }
    }

    fn check(&self, sid: &str, typ: &str, lurl: &str, sig_key: &SubjectKey) -> Result<()> {
        let data = &[sid.as_bytes(), typ.as_bytes(), lurl.as_bytes(), &self.index.to_be_bytes(), self.key.as_bytes()];
        if !self.sig.verify(&sig_key.key, data) {
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
        let sid = "s-id:shumy";

        let mut new1 = Subject::new(sid);
        let (_, skey1) = new1.evolve(sig_s1);

        let mut p1 = Profile::new("Assets", "https://profile-url.org");
        p1.chain.push(p1.evolve(sid, &sig_s1, &skey1).1);

        let mut p2 = Profile::new("Finance", "https://profile-url.org");
        p2.chain.push(p2.evolve(sid, &sig_s1, &skey1).1);

        new1
            .push(p1)
            .push(p2)
            .keys.push(skey1.clone());
        assert!(new1.check(None) == Ok(()));

        //--------------------------------------------------
        // Evolving SubjectKey
        // -------------------------------------------------
        let mut update1 = Subject::new(sid);
        update1.keys.push(new1.evolve(sig_s1).1);
        assert!(update1.check(Some(&new1)) == Ok(()));

        //--------------------------------------------------
        // Updating Profile
        // -------------------------------------------------
        let mut p3 = Profile::new("HealthCare", "https://profile-url.org");
        p3.chain.push(p3.evolve(sid, &sig_s1, &skey1).1);

        let mut update2 = Subject::new(sid);
        update2.push(p3);
        assert!(update2.check(Some(&new1)) == Ok(()));

        //--------------------------------------------------
        // Updating ProfileKey
        // -------------------------------------------------
        let p2 = new1.find("Finance", "https://profile-url.org").unwrap().clone();

        let mut empty_p2 = Profile::new("Finance", "https://profile-url.org");
        empty_p2.chain.push(p2.evolve(sid, &sig_s1, &skey1).1);

        let mut update3 = Subject::new(sid);
        update3.push(empty_p2.clone());
        assert!(update3.check(Some(&new1)) == Ok(()));
        
        //--------------------------------------------------
        // Merge and update
        // -------------------------------------------------
        new1.merge(update3);

        let mut empty_p3 = Profile::new("Finance", "https://profile-url.org");
        empty_p3.chain.push(empty_p2.evolve(sid, &sig_s1, &skey1).1);

        let mut update4 = Subject::new(sid);
        update4.push(empty_p3);
        assert!(update4.check(Some(&new1)) == Ok(()));

        // println!("ERROR: {:?}", subject3.check(Some(&subject1)));
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_incorrect_construction() {
        let sig_s1 = rnd_scalar();
        let sig_key1 = (sig_s1 * G).compress();
        let sid = "s-id:shumy";

        let mut new1 = Subject::new(sid);
        let (_, skey1) = new1.evolve(sig_s1);
        
        let mut p1 = Profile::new("Assets", "https://profile-url.org");
        p1.chain.push(p1.evolve(sid, &sig_s1, &skey1).1);

        new1
            .push(p1.clone())
            .keys.push(skey1.clone());
        assert!(new1.check(None) == Ok(()));

        //--------------------------------------------------
        // Creating Subject
        // -------------------------------------------------
        let incorrect = Subject::new(sid);
        assert!(incorrect.check(None) == Err("No key found for subject creation!"));

        let mut incorrect = Subject::new(sid);
        incorrect.keys.push(SubjectKey::new(sid, 1, sig_key1, &sig_s1, &sig_key1));
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
        incorrect.keys.push(skey2);
        assert!(incorrect.check(Some(&new1)) == Err("Incorrect index for new subject-key!"));

        let mut incorrect = Subject::new(sid);
        incorrect.keys.push(skey3);
        assert!(incorrect.check(Some(&new1)) == Err("Invalid subject-key signature!"));

        //--------------------------------------------------
        // Updating Profile
        // -------------------------------------------------
        let mut p2 = Profile::new("Assets", "https://profile-url.org");
        let mut p2_key = p1.evolve(sid, &sig_s1, &skey1).1;
        p2_key.index = 0;
        p2.chain.push(p2_key);

        //p2.new_key(sid, 0, &sig_s1, &new1.keys.last().unwrap());

        let mut update1 = Subject::new(sid);
        update1.push(p2);
        assert!(update1.check(Some(&new1)) == Err("ProfileKey is not correcly chained!"));

    }
}