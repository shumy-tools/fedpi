use std::collections::HashMap;

use log::info;
use sha2::{Sha512, Digest};

use core_fpi::{rnd_scalar, G, Result, KeyEncoder, Scalar, RistrettoPoint};
use core_fpi::shares::*;
use core_fpi::ids::*;
use core_fpi::signatures::*;
use core_fpi::messages::*;

use crate::config::Config;

pub struct Processor {
    config: Config,
    subjects: HashMap<String, Subject>,

    negotiation: Option<KeyResponse>
}

impl Processor {
    pub fn new(config: Config) -> Self {
        Self { config: config, subjects: HashMap::new(), negotiation: None }
    }

    pub fn request(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msg: Request = decode(data)?;
        match msg {
            Request::NegotiateMasterKey(negotiation) => {
                // TODO: verify if the client has authorization to fire negotiation

                if let Some(neg) = &self.negotiation {
                    if neg.session == negotiation.session {
                        let msg = Response::NegotiateMasterKey(neg.clone());
                        return encode(&msg)
                    }
                }

                let keys = self.derive_negotiation_keys(&negotiation);
                let shares = self.derive_encrypted_shares(&keys.0);

                // (session, ordered peer's list, encrypted shares, Feldman's Coefficients, peer signature)
                let neg = KeyResponse::sign(&negotiation.session, self.config.peers.iter().map(|p| p.pkey).collect(), shares.0, shares.1, &self.config.secret, &self.config.pkey);
                self.negotiation = Some(neg.clone());
                
                let msg = Response::NegotiateMasterKey(neg);
                encode(&msg)
            }
        }
    }

    pub fn validate(&self, data: &[u8]) -> Result<()> {
        let msg: Transaction = decode(data)?;
        match msg {
            Transaction::SyncSubject(subject) => self.check_subject(&subject),
            Transaction::CreateRecord(record) => {
                info!("CreateRecord - ({:#?} {:?} {:?})", record.record, record.key.encode(), record.base.encode());
                Ok(())
            }
        }
    }

    pub fn commit(&mut self, data: &[u8]) -> Result<()> {
        let msg: Transaction = decode(data)?;
        match msg {
            Transaction::SyncSubject(subject) => self.commit_subject(subject),
            Transaction::CreateRecord(record) => {
                info!("CreateRecord - ({:#?} {:?} {:?})", record.record, record.key.encode(), record.base.encode());
                Ok(())
            }
        }
    }

    fn derive_negotiation_keys(&self, neg: &KeyRequest) -> (Vec::<Scalar>, Vec::<RistrettoPoint>) {
        let secret = self.config.secret;

        let mut private_keys = Vec::<Scalar>::with_capacity(self.config.peers.len());
        let mut public_keys = Vec::<RistrettoPoint>::with_capacity(self.config.peers.len());
        for peer in self.config.peers.iter() {
            // perform a Diffie-Hellman between local and peer
            let dh = (&secret * &peer.pkey).compress();
            
            // derive secret key between peers
            let mut hasher = Sha512::new();
            hasher.input(dh.as_bytes());
            let p = Scalar::from_hash(hasher);

            // push to vectors
            public_keys.push(&p * &G);
            private_keys.push(p);
        }

        (private_keys, public_keys)
    }

    fn derive_encrypted_shares(&self, e_keys: &Vec::<Scalar>) -> (Vec<Share>, RistrettoPolynomial) {
        let n = self.config.peers.len();

        // derive secret polynomial and shares
        let y = rnd_scalar();
        let ak = Polynomial::rnd(y, self.config.threshold);
        let shares = ak.shares(n);

        // commit with Feldman's Coefficients
        let fk = &ak * &G;

        // encrypted shares
        let mut e_shares = Vec::<Share>::with_capacity(n);
        for i in 0..n {
            e_shares.push( &shares[i] + &e_keys[i] );
        }

        (e_shares, fk)
    }

    fn check_subject(&self, subject: &Subject) -> Result<()> {
        info!("check-subject - {:#?}", subject);
        
        // TODO: find subject in the database
        let current = self.subjects.get(&subject.sid);
        subject.check(current)
    }

    fn commit_subject(&mut self, subject: Subject) -> Result<()> {
        self.check_subject(&subject)?; // TODO: optimize by using local cache?
        info!("commit-subject - {:#?}", subject);
        
        // TODO: find subject in the database
        let sid = subject.sid.clone();
        let current = self.subjects.remove(&sid);
        match current {
            None => self.subjects.insert(sid, subject),
            Some(mut current) => {
                current.merge(subject);
                info!("merged-subject - {:#?}", current);
                self.subjects.insert(sid, current)
            }
        };

        Ok(())
    }
}