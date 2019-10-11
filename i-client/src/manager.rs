use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

use std::fs::{File, OpenOptions, remove_file};
use std::io::{Result, Error, ErrorKind};

use rand::prelude::*;
use std::io::prelude::*;

use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};
use clear_on_drop::clear::Clear;

use core_fpi::{G, rnd_scalar, Scalar, KeyEncoder};
use core_fpi::ids::*;
use core_fpi::authorizations::*;
use core_fpi::disclosures::*;
use core_fpi::messages::*;
use core_fpi::keys::*;
use core_fpi::shares::*;

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
    fn load(home: &str, sid: &str) -> (Option<Update>, Option<MySubject>, Option<MySubject>) {
        let upd_data = read(&select(home, sid, SType::Updating));
        let mrg_data = read(&select(home, sid, SType::Merged));
        let sto_data = read(&select(home, sid, SType::Stored));

        // read what you can and ignore the rest
        let upd: Option<Update> = match upd_data { None => None, Some(data) => deserialize(&data).ok() };
        let mrg: Option<MySubject> = match mrg_data { None => None, Some(data) => deserialize(&data).ok() };
        let sto: Option<MySubject> = match sto_data { None => None, Some(data) => deserialize(&data).ok() };
        
        (upd, mrg, sto)
    }

    fn update(home: &str, sid: &str, update: &Update) -> Result<()>{
        let data = serialize(&update).map_err(|_| Error::new(ErrorKind::Other, "Unable to encode subject!"))?;
        let file = select(home, sid, SType::Updating);

        write(&file, data)
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

    pub upd: Option<Update>,
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
        let update = Update { sid: self.sid.clone(), msg: Value::VSubject(subject), secret, profile_secrets: HashMap::new() };
        Storage::update(&self.home, &self.sid, &update)?;
        self.upd = Some(update);
        self.submit()
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
                let update = Update { sid: self.sid.clone(), msg: Value::VSubject(subject), secret, profile_secrets: HashMap::new() };
                Storage::update(&self.home, &self.sid, &update)?;
                self.upd = Some(update);
                self.submit()
            }
        }
    }

    pub fn profile(&mut self, typ: &str, lurl: &str) -> Result<()> {
        self.check_pending()?;

        match &self.sto {
            None => Err(Error::new(ErrorKind::Other, "There is not subject in the store!")),
            Some(my) => {
                let skey = my.subject.keys.last().ok_or_else(|| Error::new(ErrorKind::Other, "Subject doesn't have a key!"))?;

                let mut profile = Profile::new(typ);
                let (p_secret, location) = match my.subject.find(typ) {
                    None => profile.evolve(&self.sid, &lurl, &my.secret, skey),
                    Some(current) => current.evolve(&self.sid, &lurl, &my.secret, skey)
                };
                
                profile.push(location);

                let mut profile_secrets = HashMap::<String, Scalar>::new();
                profile_secrets.insert(ProfileLocation::pid(typ, lurl), p_secret);

                let mut subject = Subject::new(&self.sid);
                subject.push(profile);

                // sync update
                let update = Update { sid: self.sid.clone(), msg: Value::VSubject(subject), secret: my.secret, profile_secrets };
                Storage::update(&self.home, &self.sid, &update)?;
                self.upd = Some(update);
                self.submit()
            }
        }
    }

    pub fn consent(&mut self, authorized: &str, profiles: &[String]) -> Result<()> {
        self.check_pending()?;
        
        match &self.sto {
            None => Err(Error::new(ErrorKind::Other, "There is not subject in the store!")),
            Some(my) => {
                let skey = my.subject.keys.last().ok_or_else(|| Error::new(ErrorKind::Other, "Subject doesn't have a key!"))?;
                let consent = Consent::sign(&self.sid, ConsentType::Consent, authorized, profiles, &my.secret, skey);

                // sync update
                let update = Update { sid: self.sid.clone(), msg: Value::VConsent(consent), secret: my.secret, profile_secrets: HashMap::new() };
                Storage::update(&self.home, &self.sid, &update)?;
                self.upd = Some(update);
                self.submit()
            }
        }
    }

    pub fn revoke(&mut self, authorized: &str, profiles: &[String]) -> Result<()> {
        self.check_pending()?;
        
        match &self.sto {
            None => Err(Error::new(ErrorKind::Other, "There is not subject in the store!")),
            Some(my) => {
                let skey = my.subject.keys.last().ok_or_else(|| Error::new(ErrorKind::Other, "Subject doesn't have a key!"))?;
                let revoke = Consent::sign(&self.sid, ConsentType::Revoke, authorized, profiles, &my.secret, skey);

                // sync update
                let update = Update { sid: self.sid.clone(), msg: Value::VConsent(revoke), secret: my.secret, profile_secrets: HashMap::new() };
        
                Storage::update(&self.home, &self.sid, &update)?;
                self.upd = Some(update);
                self.submit()
            }
        }
    }

    pub fn disclose(&mut self, target: &str, profiles: &[String]) -> Result<()> {
        self.check_pending()?;
        
        match &self.sto {
            None => Err(Error::new(ErrorKind::Other, "There is not subject in the store!")),
            Some(my) => {
                let skey = my.subject.keys.last().ok_or_else(|| Error::new(ErrorKind::Other, "Subject doesn't have a key!"))?;
                let disclose = DiscloseRequest::sign(&self.sid, target, profiles, &my.secret, skey);

                let min = 2*self.config.threshold + 1;

                // select a random set of 2t + 1 peers
                let mut rng = rand::thread_rng();
                let mut peers = self.config.peers.clone();
                peers.shuffle(&mut rng);

                if peers.len() < min {
                    return Err(Error::new(ErrorKind::Other, "Not enought peers to process disclosure!"))
                }

                let mut results = HashMap::<usize, DiscloseResult>::with_capacity(2*self.config.threshold + 1);
                let selected = &peers[..min];
                for sel in selected.iter() {
                    let res = (self.query)(&sel, Request::Query(Query::QDiscloseRequest(disclose.clone())))?;
                    match res {
                        Response::QResult(res) => match res {
                            QResult::QDiscloseResult(dr) => {
                                let peer = self.config.peers.get(dr.sig.index).ok_or("Unexpected peer index!")
                                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                                
                                dr.check(&disclose.sig.sig.encoded, profiles, &peer.pkey)
                                    .map_err(|e| Error::new(ErrorKind::Other, e))?;

                                if results.get(&dr.sig.index).is_some() {
                                    // TODO: replace this with ignore or retry strategy?
                                    return Err(Error::new(ErrorKind::Other, "Replaced response on key disclosure!"))
                                }

                                results.insert(dr.sig.index, dr);
                            }
                        },
                        _ => return Err(Error::new(ErrorKind::Other, "Unexpected response on disclosure!"))
                    }
                    
                }

                if results.len() < min {
                    // TODO: try other peers?
                    return Err(Error::new(ErrorKind::Other, "Not enought responses to process disclosure!"))
                }
                
                // check and combine results to get pseudonyms
                let mut poly_shares = HashMap::<String, Vec<RistrettoShare>>::new();
                for (n, dr) in results.into_iter() {
                    for (typ, locs) in dr.keys.keys.into_iter() {
                        for (loc, shares) in locs.into_iter() {
                            for (i, rs) in shares.into_iter().enumerate() {
                                if n + 1 != rs.i as usize {
                                    return Err(Error::new(ErrorKind::Other, "Unexpected share index!"))
                                }

                                let key = format!("{}-{}-{}", typ, loc, i);
                                let v_shares = poly_shares.entry(key).or_insert_with(|| Vec::<RistrettoShare>::new());
                                v_shares.push(rs);
                            }
                        }
                    }
                }

                for (key, shares) in poly_shares.iter() {
                    let rpoly = RistrettoPolynomial::reconstruct(&shares);
                    if rpoly.degree() != self.config.threshold {
                        return Err(Error::new(ErrorKind::Other, "Incorrect set of shares!"))
                    }

                    let pseudo = rpoly.evaluate(&Scalar::zero());
                    println!("PSEUDONYM {} -> {}", key, pseudo.encode());
                }

                Ok(())
            }
        }
    }

    pub fn negotiate(&mut self, kid: &str) -> Result<()> {
        self.check_pending()?;
        
        match &self.sto {
            None => Err(Error::new(ErrorKind::Other, "There is not subject in the store!")),
            Some(my) => {
                let n = self.config.peers.len();

                let skey = my.subject.keys.last().ok_or_else(|| Error::new(ErrorKind::Other, "Subject doesn't have a key!"))?;
                let req = MasterKeyRequest::sign(&self.sid, kid, &self.config.peers_hash, &my.secret, skey);

                // set the results in ordered fashion
                let mut votes = Vec::<MasterKeyVote>::with_capacity(n);
                for peer in self.config.peers.iter() {
                    let res = (self.query)(peer, Request::Negotiate(Negotiate::NMasterKeyRequest(req.clone())))?;
                    match res {
                        Response::Vote(vote) => match vote {
                            Vote::VMasterKeyVote(vote) => {
                                let peer = self.config.peers.get(vote.sig.index).ok_or("Unexpected peer index!")
                                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                                
                                vote.check(&req.sig.id(), &kid, &self.config.peers_hash, self.config.peers.len(), &peer.pkey)
                                    .map_err(|e| Error::new(ErrorKind::Other, e))?;

                                if votes.get(vote.sig.index).is_some() {
                                    // TODO: replace this with ignore or retry strategy?
                                    return Err(Error::new(ErrorKind::Other, "Replaced response on key negotiation!"))
                                }

                                votes.insert(vote.sig.index, vote);
                            }
                        },
                        _ => return Err(Error::new(ErrorKind::Other, "Unexpected response on key negotiation!"))
                    }
                }

                // If all is OK, create MasterKey to commit
                let mk = MasterKey::sign(&self.sid, &req.sig.id(), kid, &self.config.peers_hash, votes, &self.config.peers_keys, &my.secret, skey)
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;

                // select a random peer
                let selection = self.config.peers.choose(&mut rand::thread_rng());

                // process master-key commit
                match selection {
                    None => Err(Error::new(ErrorKind::Other, "No peer found to send request!")),
                    Some(sel) => (self.commit)(&sel, Commit::Evidence(Evidence::EMasterKey(mk)))
                }
            }
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

    // submit an existing update
    fn submit(&mut self) -> Result<()> {
        let update = self.upd.as_ref().ok_or_else(|| Error::new(ErrorKind::Other, "No update found to commit!"))?;

        // select a random peer
        let selection = self.config.peers.choose(&mut rand::thread_rng());

        // process sync message
        match selection {
            None => return Err(Error::new(ErrorKind::Other, "No peer found to request commit!")),
            Some(sel) => (self.commit)(&sel, Commit::Value(update.msg.clone()))?
        }

        self.merge()
    }

    // merge a submitted update
    fn merge(&mut self) -> Result<()> {
        let update = self.upd.take().ok_or_else(|| Error::new(ErrorKind::Other, "No update found to merge!"))?;

        let merged = match self.sto.take() {
            None => {
                if let Value::VSubject(value) = update.msg {
                    MySubject {
                       secret: update.secret,
                       profile_secrets: update.profile_secrets,
                       subject: value,
                       auths: Authorizations::new()
                    }
                } else {
                    return Err(Error::new(ErrorKind::Other, "There is not subject in the store!"))
                }
            },

            Some(mut my) => {
                match update.msg {
                    Value::VConsent(value) => {
                        match value.typ {
                            ConsentType::Consent => my.auths.authorize(&value),
                            ConsentType::Revoke => my.auths.revoke(&value)
                        }
                    },

                    Value::VSubject(value) => {
                        my.secret = update.secret;
                        my.profile_secrets.extend(update.profile_secrets);
                        my.subject.merge(value);
                    },

                    _ => unreachable!()
                }

                my
            }
        };

        // write-ahead log
        Storage::store(&self.home, &update.sid, SType::Merged, &merged)?;
        self.mrg = Some(merged);
        self.upd = None;

        // store final result
        self.store(&update.sid)
    }

    // persistent a submitted and correctly merge update
    fn store(&mut self, sid: &str) -> Result<()> {
        if let Some(merged) = self.mrg.as_ref() {
            Storage::store(&self.home, &sid, SType::Stored, merged)?;
            self.sto = self.mrg.take();

            Storage::clean(&self.home, &sid);
        }

        Ok(())
    }
}

//-----------------------------------------------------------------------------------------------------------
// Update
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct Update {
    sid: String,
    msg: Value,

    secret: Scalar,
    profile_secrets: HashMap<String, Scalar>
}

//-----------------------------------------------------------------------------------------------------------
// MySubject
//-----------------------------------------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct MySubject {
    secret: Scalar,                                 // current subject-key secret
    profile_secrets: HashMap<String, Scalar>,       // current profile-key secrets <PID, Secret>
    
    subject: Subject,
    auths: Authorizations
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
        let p_secrets: Vec<String> = self.profile_secrets.iter().map(|(key, item)| format!("{} -> {}", key, item.encode())).collect();
        fmt.debug_struct("MySubject")
            .field("secret", &self.secret.encode())
            .field("profile_secrets", &p_secrets)
            .field("subject", &self.subject)
            .field("auths", &self.auths)
            .finish()
    }
}