use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

use std::fs::{File, OpenOptions, remove_file};
use std::io::{Result, Error, ErrorKind};
use std::io::prelude::*;

use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};
use clear_on_drop::clear::Clear;

use core_fpi::{G, uuid, rnd_scalar, Scalar, KeyEncoder, RistrettoPoint};
use core_fpi::ids::*;
use core_fpi::messages::*;
use core_fpi::keys::*;

use crate::config::{Peer, Config};

fn select(home: &str, sid: &str, typ: SType) -> String {
    match typ {
        SType::Updating => format!("{}/{}.upd", home, sid),
        SType::Merged => format!("{}/{}.mrg", home, sid),
        SType::Stored => format!("{}/{}.sto", home, sid),
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
    fn load(home: &str, sid: &str) -> (Option<MySubject>, Option<MySubject>, Option<MySubject>) {
        let upd_data = read(&select(home, sid, SType::Updating));
        let mrg_data = read(&select(home, sid, SType::Merged));
        let sto_data = read(&select(home, sid, SType::Stored));

        // read what you can and ignore the rest
        let upd: Option<MySubject> = match upd_data { None => None, Some(data) => deserialize(&data).ok() };
        let mrg: Option<MySubject> = match mrg_data { None => None, Some(data) => deserialize(&data).ok() };
        let sto: Option<MySubject> = match sto_data { None => None, Some(data) => deserialize(&data).ok() };
        
        (upd, mrg, sto)
    }

    fn store(home: &str, sid: &str, typ: SType, my: &MySubject) -> Result<()> {
        let data = serialize(&my).map_err(|_| Error::new(ErrorKind::Other, "Unable to encode subject!"))?;
        let file = select(home, sid, typ);

        write(&file, data)
    }

    fn reset(home: &str, sid: &str) {
        Storage::clean(home, sid);
        let sto = select(home, sid, SType::Stored);
        remove_file(&sto).ok();
    }

    fn clean(home: &str, sid: &str) {
        let upd = select(home, sid, SType::Updating);
        let mrg = select(home, sid, SType::Merged);

        // nothing to do if it can't remove
        remove_file(&upd).ok();
        remove_file(&mrg).ok();
    }
}

//-----------------------------------------------------------------------------------------------------------
// SubjectManager
//-----------------------------------------------------------------------------------------------------------
pub struct SubjectManager<F, Q> where F: Fn(&Peer, Commit) -> Result<()>, Q: Fn(&Peer, Request) -> Result<Response> {
    pub home: String,
    pub sid: String,
    pub config: Config,

    pub upd: Option<MySubject>,
    pub mrg: Option<MySubject>,
    pub sto: Option<MySubject>,

    commit: F,
    query: Q
}

impl<F: Fn(&Peer, Commit) -> Result<()>, Q: Fn(&Peer, Request) -> Result<Response>> SubjectManager<F, Q> {
    pub fn new(home: &str, sid: &str, cfg: Config, commit: F, query: Q) -> Self {
        let res = Storage::load(home, sid);
        Self { home: home.into(), sid: sid.into(), config: cfg, upd: res.0, mrg: res.1, sto: res.2, commit, query }
    }

    pub fn reset(&mut self) {
        Storage::reset(&self.home, &self.sid);
    }

    pub fn create(&mut self) -> Result<()> {
        self.check_pending()?;
        if self.sto.is_some() {
            return Err(Error::new(ErrorKind::Other, "You already have a subject in the store!"))
        }

        let secret = rnd_scalar();
        let skey = secret * G;

        let mut subject = Subject::new(&self.sid);
        subject.keys.push(SubjectKey::sign(&self.sid, 0, skey, &secret, &skey));

        // sync update
        let update = MySubject { secret, profile_secrets: HashMap::new(), subject };
        self.sync_subject(update)
    }

    pub fn evolve(&mut self) -> Result<()> {
        self.check_pending()?;

        match &self.sto {
            None => Err(Error::new(ErrorKind::Other, "There is not subject in the store!")),
            Some(my) => {
                let (secret, skey) = my.subject.evolve(my.secret);

                let mut subject = Subject::new(&self.sid);
                subject.keys.push(skey);

                // sync update
                let update = MySubject { secret, profile_secrets: HashMap::new(), subject };
                self.sync_subject(update)
            }
        }
    }

    pub fn profile(&mut self, typ: &str, lurl: &str) -> Result<()> {
        self.check_pending()?;

        match &self.sto {
            None => Err(Error::new(ErrorKind::Other, "There is not subject in the store!")),
            Some(my) => {
                let skey = my.subject.keys.last().ok_or_else(|| Error::new(ErrorKind::Other, "Subject doesn't have a key!"))?;

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
                let update = MySubject { secret: my.secret, profile_secrets, subject: sub };
                self.sync_subject(update)
            }
        }
    }

    pub fn negotiate(&mut self) -> Result<()> {
        let session = uuid();
        let n = self.config.peers.len();
        let req = MasterKeyRequest::sign(&session, &self.config.secret, self.config.pkey);

        // set the results in ordered fashion
        let mut votes = Vec::<MasterKeyVote>::with_capacity(n);
        for peer in self.config.peers.iter() {
            let res = (self.query)(peer, Request::Negotiate(Negotiate::NMasterKeyRequest(req.clone())))?;
            match res {
                Response::Vote(vote) => match vote {
                    Vote::VMasterKeyVote(vote) => {
                        if votes.get(vote.sig.index).is_some() {
                            // TODO: replace this with ignore or retry strategy?
                            return Err(Error::new(ErrorKind::Other, "Replaced response on key negotiation!"))
                        }

                        if vote.sig.index > n-1 {
                            // TODO: replace this with ignore or retry strategy?
                            return Err(Error::new(ErrorKind::Other, "Unexpected peer index on key negotiation!"))
                        }

                        votes.insert(vote.sig.index, vote);
                    }
                }
            }
        }

        // If all is OK, create MasterKey to commit
        let pkeys: Vec<RistrettoPoint> = self.config.peers.iter().map(|p| p.pkey).collect();
        let mk = MasterKey::sign(&session, &self.config.peers_hash, votes, self.config.peers.len(), &pkeys, &self.config.secret, self.config.pkey)
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        // select a random peer
        use rand::seq::SliceRandom;
        let selection = self.config.peers.choose(&mut rand::thread_rng());

        // process master-key commit
        match selection {
            None => Err(Error::new(ErrorKind::Other, "No peer found to send request!")),
            Some(sel) => (self.commit)(&sel, Commit::Evidence(Evidence::EMasterKey(mk)))
        }
    }

    fn check_pending(&self) -> Result<()> {
        if self.upd.is_some() {
            return Err(Error::new(ErrorKind::Other, "There is a pending synchronization in the log!"))
        }

        if self.mrg.is_some() {
            return Err(Error::new(ErrorKind::Other, "There is a pending synchronization in the log!"))
        }

        Ok(())
    }

    //TODO: improve performance. Try to remove the many clone() calls!
    fn sync_subject(&mut self, update: MySubject) -> Result<()> {
        let secret = update.secret;
        let profile_secrets = update.profile_secrets.clone();
        
        let subject = update.subject.clone();
        let sid = subject.sid.clone();

        Storage::store(&self.home, &self.sid, SType::Updating, &update)?;
        self.upd = Some(update);

        // select a random peer
        use rand::seq::SliceRandom;
        let selection = self.config.peers.choose(&mut rand::thread_rng());

        // process sync message
        match selection {
            None => return Err(Error::new(ErrorKind::Other, "No peer found to send request!")),
            Some(sel) => (self.commit)(&sel, Commit::Value(Value::VSubject(subject.clone())))?
        }

        // merge with existent
        let merged = match self.sto.take() {
            None => self.upd.take().unwrap(),
            Some(mut stored) => {
                stored.secret = secret;
                stored.profile_secrets.extend(profile_secrets);

                stored.subject.merge(subject);
                Storage::store(&self.home, &self.sid, SType::Merged, &stored)?;
                stored
            }
        };

        // store final result
        Storage::store(&self.home, &self.sid, SType::Stored, &merged)?;
        self.sto = Some(merged);
        Storage::clean(&self.home, &sid);

        Ok(())
    }
}

//-----------------------------------------------------------------------------------------------------------
// MySubject
//-----------------------------------------------------------------------------------------------------------
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