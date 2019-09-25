use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

use std::fs::{File, OpenOptions, remove_file};
use std::io::{Result, Error, ErrorKind};
use std::io::prelude::*;

use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};

use core_fpi::{G, rnd_scalar, Scalar, KeyEncoder};
use core_fpi::ids::*;
use core_fpi::messages::Transaction;

fn select(sid: &str, typ: SType) -> String {
    match typ {
        SType::Updating => format!("{}.upd", sid),
        SType::Merged => format!("{}.mrg", sid),
        SType::Stored => format!("{}.sto", sid),
    }
}

fn read(name: &str) -> Option<Vec<u8>> {
    let file = File::open(name);

    // no problem if it doens't exists
    let mut file = match file {
        Ok(file) => file,
        Err(error) => {
            if let ErrorKind::NotFound = error.kind()  {
                return None
            } else {
                panic!("Problems opening the file ({:?}): {:?}", name, error)
            }
        }
    };
    
    let mut data = Vec::<u8>::new();
    if let Err(e) = file.read_to_end(&mut data) {
        panic!("Problems reading the file ({:?}): {:?}", name, e)
    }
    
    Some(data)
}

fn write(name: &str, data: Vec<u8>) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create(true).open(name)?;
    file.write_all(&data)
}

//-----------------------------------------------------------------------------------------------------------
// Storage
//-----------------------------------------------------------------------------------------------------------
enum SType { Updating, Merged, Stored }

struct Storage {}

impl Storage {
    fn load(sid: &str) -> (Option<MySubject>, Option<MySubject>, Option<MySubject>) {
        let upd_data = read(&select(sid, SType::Updating));
        let mrg_data = read(&select(sid, SType::Merged));
        let sto_data = read(&select(sid, SType::Stored));

        // read what you can and ignore the rest
        let upd: Option<MySubject> = match upd_data { None => None, Some(data) => deserialize(&data).ok() };
        let mrg: Option<MySubject> = match mrg_data { None => None, Some(data) => deserialize(&data).ok() };
        let sto: Option<MySubject> = match sto_data { None => None, Some(data) => deserialize(&data).ok() };
        
        (upd, mrg, sto)
    }

    fn store(sid: &str, typ: SType, my: &MySubject) -> Result<()> {
        let data = serialize(&my).map_err(|_| Error::new(ErrorKind::Other, "Unable to encode subject!"))?;
        let file = select(sid, typ);

        write(&file, data)
    }

    fn reset(sid: &str) {
        Storage::clean(sid);
        let sto = select(sid, SType::Stored);
        remove_file(&sto).ok();
    }

    fn clean(sid: &str) {
        let upd = select(sid, SType::Updating);
        let mrg = select(sid, SType::Merged);

        // nothing to do if it can't remove
        remove_file(&upd).ok();
        remove_file(&mrg).ok();
    }
}

//-----------------------------------------------------------------------------------------------------------
// SubjectManager
//-----------------------------------------------------------------------------------------------------------
pub struct SubjectManager<F> where F: Fn(Transaction) -> Result<()> {
    pub sid: String,

    pub upd: Option<MySubject>,
    pub mrg: Option<MySubject>,
    pub sto: Option<MySubject>,

    sync: F
}

impl<F: Fn(Transaction) -> Result<()>> SubjectManager<F> {
    pub fn new(sid: &str, sync: F) -> Self {
        let res = Storage::load(sid);
        Self { sid: sid.into(), upd: res.0, mrg: res.1, sto: res.2, sync: sync }
    }

    pub fn reset(&mut self) {
        Storage::reset(&self.sid);
    }

    pub fn create(&mut self) -> Result<()> {
        self.check_pending()?;
        if let Some(_) = self.sto {
            return Err(Error::new(ErrorKind::Other, "You already have a subject in the store!"))
        }

        let secret = rnd_scalar();
        let skey = secret * G;

        let mut sub = Subject::new(&self.sid);
        sub.keys.push(SubjectKey::new(&self.sid, 0, skey, &secret, &skey));

        // sync update
        let update = MySubject { secret: secret, profile_secrets: HashMap::new(), subject: sub };
        self.sync_subject(update)
    }

    pub fn evolve(&mut self) -> Result<()> {
        self.check_pending()?;

        match &self.sto {
            None => return Err(Error::new(ErrorKind::Other, "There is not subject in the store!")),
            Some(my) => {
                let (secret, skey) = my.subject.evolve(my.secret);

                let mut sub = Subject::new(&self.sid);
                sub.keys.push(skey);

                // sync update
                let update = MySubject { secret: secret, profile_secrets: HashMap::new(), subject: sub };
                self.sync_subject(update)
            }
        }
    }

    pub fn profile(&mut self, typ: &str, lurl: &str) -> Result<()> {
        self.check_pending()?;

        match &self.sto {
            None => return Err(Error::new(ErrorKind::Other, "There is not subject in the store!")),
            Some(my) => {
                let skey = my.subject.keys.last().ok_or(Error::new(ErrorKind::Other, "Subject doesn't have a key!"))?;

                let mut profile = Profile::new(typ, lurl);
                let (p_secret, pkey) = match my.subject.find(typ, lurl) {
                    None => profile.evolve(&self.sid, &my.secret, skey),
                    Some(current) => current.evolve(&self.sid, &my.secret, skey)
                };

                profile.chain.push(pkey);
                
                let mut profile_secrets = HashMap::<String, Scalar>::new();
                profile_secrets.insert(profile.id(), p_secret);

                let mut sub = Subject::new(&self.sid);
                sub.push(profile);

                // sync update
                let update = MySubject { secret: my.secret, profile_secrets: profile_secrets, subject: sub };
                self.sync_subject(update)
            }
        }
    }

    fn check_pending(&self) -> Result<()> {
        if let Some(_) = self.upd {
            return Err(Error::new(ErrorKind::Other, "There is a pending synchronization in the log!"))
        }

        if let Some(_) = self.mrg {
            return Err(Error::new(ErrorKind::Other, "There is a pending synchronization in the log!"))
        }

        Ok(())
    }

    //TODO: improve performance. Try to remove the many clone() calls!
    fn sync_subject(&mut self, update: MySubject) -> Result<()> {
        let secret = update.secret.clone();
        let profile_secrets = update.profile_secrets.clone();
        
        let subject = update.subject.clone();
        let sid = subject.sid.clone();

        Storage::store(&self.sid, SType::Updating, &update)?;
        self.upd = Some(update);

        // process sync message
        (self.sync)(Transaction::SyncSubject(subject.clone()))?;

        // merge with existent
        let merged = match self.sto.take() {
            None => self.upd.take().unwrap(),
            Some(mut stored) => {
                stored.secret = secret;
                stored.profile_secrets.extend(profile_secrets);

                stored.subject.merge(subject);
                Storage::store(&self.sid, SType::Merged, &stored)?;
                stored
            }
        };

        // store final result
        Storage::store(&self.sid, SType::Stored, &merged)?;
        self.sto = Some(merged);
        Storage::clean(&sid);

        Ok(())
    }
}

//-----------------------------------------------------------------------------------------------------------
// MySubject
//-----------------------------------------------------------------------------------------------------------
use clear_on_drop::clear::Clear;

#[derive(Serialize, Deserialize, Clone)]
pub struct MySubject {
    secret: Scalar,                                 // current subject-key secret
    profile_secrets: HashMap<String, Scalar>,       // current profile-key secrets <PID, Secret>

    subject: Subject
}

impl Drop for MySubject {
    fn drop(&mut self) {
        self.secret.clear();
        for item in self.profile_secrets.iter_mut() {
            item.1.clear();
        }
    }
}

impl Debug for MySubject {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("MySubject")
            .field("secret", &self.secret.encode())
            .field("subject", &self.subject)
            .finish()
    }
}