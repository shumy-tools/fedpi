use std::fmt::{Debug, Formatter};
use std::collections::BTreeMap;

use serde::{Serialize, Deserialize};

use crate::crypto::signatures::IndSignature;
use crate::{G, rnd_scalar, Result, KeyEncoder, Scalar, RistrettoPoint};

//-----------------------------------------------------------------------------------------------------------
// Subject
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Subject {
    pub sid: String,                                            // Subject ID - <Name>
    pub keys: Vec<SubjectKey>,                                  // All subject keys
    pub profiles: BTreeMap<String, Profile>,                    // All subject profiles <typ:lurl>

    #[serde(skip)] _phantom: () // force use of constructor
}

impl Debug for Subject {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Subject")
            .field("sid", &self.sid)
            .field("keys", &self.keys)
            .field("profiles", &self.profiles.values())
            .finish()
    }
}

impl Subject {
    pub fn new(sid: &str) -> Self {
        Self { sid: sid.into(), ..Default::default() }
    }

    pub fn evolve(&self, sig_s: Scalar) -> (Scalar, SubjectKey) {
        let sig_key = sig_s * G;
        match self.keys.last() {
            None => (sig_s, SubjectKey::sign(&self.sid, 0, sig_key, &sig_s, &sig_key)),
            Some(active) => {
                let secret = rnd_scalar();
                let skey = secret * G;
                (secret, SubjectKey::sign(&self.sid, active.sig.index + 1, skey, &sig_s, &sig_key))
            }
        }
    }

    pub fn find(&self, typ: &str) -> Option<&Profile> {
        self.profiles.get(typ)
    }

    pub fn push(&mut self, profile: Profile) -> &mut Self {
        self.profiles.insert(profile.typ.clone(), profile);
        self
    }

    pub fn merge(&mut self, update: Subject) {
        self.keys.extend_from_slice(&update.keys);

        for (typ, item) in update.profiles.into_iter() {
            match self.profiles.get_mut(&typ) {
                None => {self.profiles.insert(typ, item);},
                Some(ref mut current) => current.merge(item)
            }
        }
    }

    pub fn check(&self, current: Option<Subject>) -> Result<()> {
        match current {
            None => self.check_create(),
            Some(ref current) => {
                match self.keys.len() {
                    0 => self.check_update(current),
                    1 => self.check_evolve(current),
                    _ => Err("Incorrect number of keys for subject sync!".into())
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
            return Err("Incorrect key index for subject creation!".into())
        }

        // a self-signed SubjectKey
        active_key.check(&self.sid, active_key)?;

        // check profiles (it's ok if there are no profiles)
        let empty_map = BTreeMap::<String, Profile>::new();
        Subject::check_profiles(&self.sid, &self.profiles, &empty_map, active_key)
    }

    fn check_evolve(&self, current: &Subject) -> Result<()>  {
        // check the key
        let active_key = current.keys.last().ok_or("Current subject must have an active key!")?;
        let new_key = self.keys.last().ok_or("No subject-key at expected index!")?;

        if active_key.sig.index + 1 != new_key.sig.index {
            return Err("Incorrect index for new subject-key!".into())
        }

        new_key.check(&self.sid, active_key)?;

        if !self.profiles.is_empty() {
            return Err("Subject key-evolution cannot have profiles!".into())
        }

        Ok(())
    }

    fn check_update(&self, current: &Subject) -> Result<()> {
        if self.sid != current.sid {
            // if it executes it's a bug in the code
            return Err("self.sid != update.sid".into())
        }

        // get active key for subject
        let active_key = current.keys.last().ok_or("Current subject must have an active key!")?;

        // check profiles
        if self.profiles.is_empty() {
            return Err("Subject update must have at least one profile!".into())
        }

        Subject::check_profiles(&self.sid, &self.profiles, &current.profiles, active_key)
    }

    fn check_profiles(sid: &str, profiles: &BTreeMap<String, Profile>, current: &BTreeMap<String, Profile>, sig_key: &SubjectKey) -> Result<()> {
        for (typ, item) in profiles.iter() {
            if *typ != item.typ {
                return Err("Incorrect profile map-key!".into())
            }

            item.check(sid, current.get(typ), sig_key)?;
        }

        Ok(())
    }
}

//-----------------------------------------------------------------------------------------------------------
// SubjectKey
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct SubjectKey {
    pub key: RistrettoPoint,                        // The public key
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
    pub fn sign(sid: &str, index: usize, skey: RistrettoPoint, sig_s: &Scalar, sig_key: &RistrettoPoint) -> Self {
        let sig_data = Self::data(sid, index, &skey);
        let sig = IndSignature::sign(index, sig_s, sig_key, &sig_data);
        
        Self { key: skey, sig, _phantom: () }
    }

    fn check(&self, sid: &str, sig_key: &SubjectKey) -> Result<()> {
        let sig_data = Self::data(sid, self.sig.index, &self.key);
        if !self.sig.verify(&sig_key.key, &sig_data) {
            return Err("Invalid subject-key signature!".into())
        }

        Ok(())
    }

    fn data(sid: &str, index: usize, key: &RistrettoPoint) -> [Vec<u8>; 3] {
        let c_key = key.compress();

        // These unwrap() should never fail, or it's a serious code bug!
        let b_sid = bincode::serialize(sid).unwrap();
        let b_index = bincode::serialize(&index).unwrap();
        let b_key = bincode::serialize(&c_key).unwrap();

        [b_sid, b_index, b_key]
    }
}

//-----------------------------------------------------------------------------------------------------------
// Profile
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Profile {
    pub typ: String,                                    // Profile Type ex: HealthCare, Financial, Assets, etc
    pub locations: BTreeMap<String, ProfileLocation>,    // Location <lurl>
    
    #[serde(skip)] _phantom: (), // force use of constructor
    
    // TODO: how to manage replicas without using identity keys?
}

impl Debug for Profile {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Profile")
            .field("typ", &self.typ)
            .field("locations", &self.locations.values())
            .finish()
    }
}

impl Profile {
    pub fn new(typ: &str) -> Self {
        Self { typ: typ.into(), ..Default::default() }
    }

    pub fn find(&self, lurl: &str) -> Option<&ProfileLocation> {
        self.locations.get(lurl)
    }

    pub fn evolve(&self, sid: &str, lurl: &str, sig_s: &Scalar, sig_key: &SubjectKey) -> (Scalar, ProfileLocation) {
        match self.locations.get(lurl) {
            None => {
                let mut location = ProfileLocation::new(lurl);
                let (secret, pkey) = location.evolve(sid, &self.typ, sig_s, sig_key);
                location.chain.push(pkey);
                (secret, location)
            },
            Some(location) => {
                let (secret, pkey) = location.evolve(sid, &self.typ, sig_s, sig_key);

                let mut location = ProfileLocation::new(lurl);
                location.chain.push(pkey);
                (secret, location)
            }
        }
    }

    pub fn push(&mut self, location: ProfileLocation) -> &mut Self {
        self.locations.insert(location.lurl.clone(), location);
        self
    }

    fn merge(&mut self, update: Profile) {
        for (lurl, item) in update.locations.into_iter() {
            match self.locations.get_mut(&lurl) {
                None => {self.locations.insert(lurl, item);},
                Some(ref mut current) => current.merge(item)
            }
        }
    }

    fn check(&self, sid: &str, current: Option<&Profile>, sig_key: &SubjectKey) -> Result<()> {
        // TODO: check "typ"?

        for (lurl, item) in self.locations.iter() {
            if *lurl != item.lurl {
                return Err("Incorrect profile-location map-key!".into())
            }

            let current_location = match current {
                None => None,
                Some(current) => {
                    current.locations.get(lurl)
                }
            };

            item.check(sid, &self.typ, current_location, sig_key)?;
        }

        Ok(())
    }
}

//-----------------------------------------------------------------------------------------------------------
// ProfileLocation
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ProfileLocation {
    pub lurl: String,                           // Location URL (URL for the profile server)
    pub chain: Vec<ProfileKey>,

    #[serde(skip)] _phantom: () // force use of constructor
}

impl Debug for ProfileLocation {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("ProfileLocation")
            .field("lurl", &self.lurl)
            .field("chain", &self.chain)
            .finish()
    }
}

impl ProfileLocation {
    pub fn pid(typ: &str, lurl: &str) -> String {
        format!("{}@{}", typ, lurl).to_string()
    }

    pub fn new(lurl: &str) -> Self {
        Self { lurl: lurl.into(), ..Default::default() }
    }

    pub fn evolve(&self, sid: &str, typ: &str, sig_s: &Scalar, sig_key: &SubjectKey) -> (Scalar, ProfileKey) {
        let secret = rnd_scalar();
        let key = secret * G;

        let pkey = match self.chain.last() {
            None => ProfileKey::sign(sid, typ, &self.lurl, 0, key, sig_s, sig_key),
            Some(active) => ProfileKey::sign(sid, typ, &self.lurl, active.index + 1, key, sig_s, sig_key)
        };

        (secret, pkey)
    }

    fn merge(&mut self, update: ProfileLocation) {
        self.chain.extend(update.chain);
    }

    fn check(&self, sid: &str, typ: &str, current: Option<&ProfileLocation>, sig_key: &SubjectKey) -> Result<()> {
        // check profile
        let mut prev = match current {
            None => {
                // TODO: check "typ" and "lurl" fields?
                -1
            },
            Some(current) => {
                let pkey = current.chain.last().ok_or("Current profile-location must have keys!")?;
                pkey.index as i32
            }
        };

        // check profile keys
        if self.chain.is_empty() {
            return Err("Profile-location must have keys!".into())
        }

        for item in self.chain.iter() {
            if prev + 1 != item.index as i32 {
                return Err("ProfileKey is not correcly chained!".into())
            }

            item.check(sid, typ, &self.lurl, sig_key)?;
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
    pub key: RistrettoPoint,                // The profile public key
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
    pub fn sign(sid: &str, typ: &str, lurl: &str, index: usize, skey: RistrettoPoint, sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let sig_data = Self::data(sid, typ, lurl, index, &skey);
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, &sig_data);
        
        Self { index, key: skey, sig, _phantom: () }
    }

    fn check(&self, sid: &str, typ: &str, lurl: &str, sig_key: &SubjectKey) -> Result<()> {
        let sig_data = Self::data(sid, typ, lurl, self.index, &self.key);
        if !self.sig.verify(&sig_key.key, &sig_data) {
            return Err("Invalid profile-key signature!".into())
        }

        Ok(())
    }

    fn data(sid: &str, typ: &str, lurl: &str, index: usize, key: &RistrettoPoint) -> [Vec<u8>; 5] {
        let c_key = key.compress();

        // These unwrap() should never fail, or it's a serious code bug!
        let b_sid = bincode::serialize(sid).unwrap();
        let b_typ = bincode::serialize(typ).unwrap();
        let b_lurl = bincode::serialize(lurl).unwrap();
        let b_index = bincode::serialize(&index).unwrap();
        let b_key = bincode::serialize(&c_key).unwrap();

        [b_sid, b_typ, b_lurl, b_index, b_key]
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

        let mut p1 = Profile::new("Assets");
        p1.push(p1.evolve(&sid, "https://profile-url.org", &sig_s1, &skey1).1);

        let mut p2 = Profile::new("Finance");
        p2.push(p2.evolve(&sid, "https://profile-url.org", &sig_s1, &skey1).1);

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
        assert!(update1.check(Some(new1.clone())) == Ok(()));

        //--------------------------------------------------
        // Updating Profile
        // -------------------------------------------------
        let mut p3 = Profile::new("HealthCare");
        p3.push(p3.evolve(sid, "https://profile-url.org", &sig_s1, &skey1).1);

        let mut update2 = Subject::new(sid);
        update2.push(p3);
        assert!(update2.check(Some(new1.clone())) == Ok(()));

        //--------------------------------------------------
        // Updating ProfileKey
        // -------------------------------------------------
        let p2 = new1.find("Finance").unwrap().clone();

        let mut empty_p2 = Profile::new("Finance");
        empty_p2.push(p2.evolve(sid, "https://profile-url.org", &sig_s1, &skey1).1);

        let mut update3 = Subject::new(sid);
        update3.push(empty_p2.clone());
        assert!(update3.check(Some(new1.clone())) == Ok(()));
        
        //--------------------------------------------------
        // Merge and update
        // -------------------------------------------------
        new1.merge(update3);

        let mut empty_p3 = Profile::new("Finance");
        empty_p3.push(empty_p2.evolve(sid, "https://profile-url.org", &sig_s1, &skey1).1);

        let mut update4 = Subject::new(sid);
        update4.push(empty_p3);
        assert!(update4.check(Some(new1.clone())) == Ok(()));

        // println!("ERROR: {:?}", subject3.check(Some(&subject1)));
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_incorrect_construction() {
        let sig_s1 = rnd_scalar();
        let sig_key1 = sig_s1 * G;
        let sid = "s-id:shumy";

        let mut new1 = Subject::new(sid);
        let (_, skey1) = new1.evolve(sig_s1);
        
        let mut p1 = Profile::new("Assets");
        p1.push(p1.evolve(sid, "https://profile-url.org", &sig_s1, &skey1).1);

        new1
            .push(p1.clone())
            .keys.push(skey1.clone());
        assert!(new1.check(None) == Ok(()));

        //--------------------------------------------------
        // Creating Subject
        // -------------------------------------------------
        let incorrect = Subject::new(sid);
        assert!(incorrect.check(None) == Err("No key found for subject creation!".into()));

        let mut incorrect = Subject::new(sid);
        incorrect.keys.push(SubjectKey::sign(sid, 1, sig_key1, &sig_s1, &sig_key1));
        assert!(incorrect.check(None) == Err("Incorrect key index for subject creation!".into()));

        //--------------------------------------------------
        // Evolving SubjectKey
        // -------------------------------------------------
        let sig_s2 = rnd_scalar();
        let sig_key2 = sig_s2 * G;

        // try to evolve with wrong index and self-signed!
        let skey2 = SubjectKey::sign(sid, 0, sig_key2, &sig_s1, &sig_key1);
        let skey3 = SubjectKey::sign(sid, 1, sig_key2, &sig_s2, &sig_key2);

        let mut incorrect = Subject::new(sid);
        incorrect.keys.push(skey2);
        assert!(incorrect.check(Some(new1.clone())) == Err("Incorrect index for new subject-key!".into()));

        let mut incorrect = Subject::new(sid);
        incorrect.keys.push(skey3);
        assert!(incorrect.check(Some(new1.clone())) == Err("Invalid subject-key signature!".into()));

        //--------------------------------------------------
        // Updating Profile
        // -------------------------------------------------
        let mut p2 = Profile::new("Assets");
        let mut p2_loc = p1.evolve(sid, "https://profile-url.org", &sig_s1, &skey1).1;
        let mut p2_key = &mut p2_loc.chain[0];
        p2_key.index = 0usize;
        p2.push(p2_loc);

        let mut update1 = Subject::new(sid);
        update1.push(p2);
        assert!(update1.check(Some(new1.clone())) == Err("ProfileKey is not correcly chained!".into()));

    }
}