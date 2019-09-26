use std::sync::Arc;
use log::info;
use sha2::{Sha512, Digest};

use core_fpi::{rnd_scalar, G, Result, Scalar, RistrettoPoint};
use core_fpi::shares::*;
use core_fpi::messages::*;
use core_fpi::negotiation::*;

use crate::config::Config;

pub struct MasterKeyHandler {
    config: Arc<Config>,
    negotiation: Option<KeyResponse>,
    current: Option<MasterKey>
}

impl MasterKeyHandler {
    pub fn new(cfg: Arc<Config>) -> Self {
        Self {config: cfg, negotiation: None, current: None }
    }

    pub fn negotiate(&mut self, req: KeyRequest) -> Result<Vec<u8>> {
        // verify if the client has authorization to fire negotiation
        if req.sig.key != self.config.mng_key || !req.verify() {
            return Err("Client has not authorization to negotiate master-key!")
        }

        if let Some(neg) = &self.negotiation {
            if neg.session == req.session {
                let msg = Response::NegotiateKey(neg.clone());
                return encode(&msg)
            }
        }

        let keys = self.derive_negotiation_keys(&req);
        let shares = self.derive_encrypted_shares(&keys.0);

        // (session, ordered peer's list, encrypted shares, Feldman's Coefficients, peer signature)
        let peer_keys: Vec<RistrettoPoint> = self.config.peers.iter().map(|p| p.pkey).collect();
        let neg = KeyResponse::sign(&req.session, peer_keys, shares.0, keys.1, shares.1, &self.config.secret, &self.config.pkey);
        self.negotiation = Some(neg.clone());
        
        let msg = Response::NegotiateKey(neg);
        encode(&msg)
    }

    pub fn check(&self, mkey: &MasterKey) -> Result<()> {
        info!("check-key - {:#?}", mkey.session);

        let peer_keys: Vec<RistrettoPoint> = self.config.peers.iter().map(|p| p.pkey).collect();
        mkey.check(&peer_keys)
    }

    pub fn commit(&mut self, mkey: MasterKey) -> Result<()> {
        self.check(&mkey)?; // TODO: optimize by using local cache?
        info!("commit-key - {:#?}", mkey.session);
        
        // TODO: sould insert a key evolution in the DB
        self.current = Some(mkey);

        /* TODO: how to to evolve all existing pseudonyms?
            * This is an issue, because the pseudonyms are not in the federated network!
            * Contact each p-server to update (delivering the evolution-key)?
            * Or, mantain the respective master-key (base-point) for each Profile?
        */

        //TODO: should return the new public-key
        Ok(())
    }

    fn derive_negotiation_keys(&self, neg: &KeyRequest) -> (Vec::<Scalar>, Vec::<RistrettoPoint>) {
        let n = self.config.peers.len();
        let secret = self.config.secret;

        let mut private_keys = Vec::<Scalar>::with_capacity(n);
        let mut public_keys = Vec::<RistrettoPoint>::with_capacity(n);
        for peer in self.config.peers.iter() {
            // perform a Diffie-Hellman between local and peer
            let dh = (&secret * &peer.pkey).compress();
            
            // derive secret key between peers
            let mut hasher = Sha512::new();
            hasher.input(dh.as_bytes());
            hasher.input(neg.session.as_bytes());
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
}