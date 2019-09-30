use std::sync::Arc;
use log::info;
use sha2::{Sha512, Digest};
use clear_on_drop::clear::Clear;

use core_fpi::{rnd_scalar, G, Result, KeyEncoder, Scalar, RistrettoPoint};
use core_fpi::shares::*;
use core_fpi::messages::*;
use core_fpi::keys::*;

use crate::config::Config;

pub struct MasterKeyHandler {
    config: Arc<Config>,
    vote: Option<MasterKeyVote>,
    evidence: Option<MasterKey>
}

impl MasterKeyHandler {
    pub fn new(cfg: Arc<Config>) -> Self {
        Self {config: cfg, vote: None, evidence: None }
    }

    pub fn request(&mut self, req: MasterKeyRequest) -> Result<Vec<u8>> {
        // verify if the client has authorization to fire negotiation
        if req.sig.key != self.config.admin || !req.verify() {
            return Err("Client has not authorization to negotiate master-key!")
        }

        if let Some(vote) = &self.vote {
            if vote.session == req.session {
                let msg = Response::Vote(Vote::VMasterKeyVote(vote.clone()));
                return encode(&msg)
            }
        }

        let e_keys = self.derive_encryption_keys(&req.session);         // encryption keys (e_i)
        let p_keys = e_keys.0.iter().map(|e_i| e_i * &G).collect();     // public keys (e_i * G -> E_i)
        let e_shares = self.derive_encrypted_shares(&e_keys);           // encrypted shares and Feldman's Coefficients (e_i + y_i -> p_i, A_k)

        // (session, ordered peer's list, encrypted shares, Feldman's Coefficients, peer signature)
        let vote = MasterKeyVote::sign(&req.session, &self.config.peers_hash, e_shares.0, p_keys, e_shares.1, &self.config.secret, &self.config.pkey, self.config.index);
        self.vote = Some(vote.clone());

        let msg = Response::Vote(Vote::VMasterKeyVote(vote));
        encode(&msg)
    }

    pub fn check(&self, mkey: &MasterKey) -> Result<()> {
        info!("CHECK-KEY - (session = {:#?})", mkey.session);

        // verify if the client has authorization to commit evidence (signature is verified on check)
        if mkey.sig.key != self.config.admin {
            return Err("Client has not authorization to commit master-key evidence!")
        }

        let pkeys: Vec<RistrettoPoint> = self.config.peers.iter().map(|p| p.pkey).collect();
        mkey.check(&self.config.peers_hash, self.config.peers.len(), &pkeys)
    }

    pub fn commit(&mut self, mkey: MasterKey) -> Result<()> {
        self.check(&mkey)?; // TODO: optimize by using local cache?
        info!("COMMIT-KEY - (session = {:#?})", mkey.session);
        
        let n = self.config.peers.len();

        let e_shares = mkey.extract(self.config.index);                 // encrypted shares, Feldman's Coefs and PublicKey (e_i + y_i -> p_i, A_k, Y)
        let e_keys = self.derive_encryption_keys(&mkey.session);        // encryption keys (e_i)

        if e_shares.0.len() != n || e_keys.0.len() != n {
            return Err("Incorrect sizes on MasterKey commit (#e_shares != n || #e_keys != n)!")
        }

        // recover an check encrypted shares
        let share_index = e_shares.0[0].i;
        let mut shares = Vec::<Share>::with_capacity(n);
        for (i, e_i) in e_keys.0.iter().enumerate() {
            if e_shares.0[i].i != share_index {
                return Err("Invalid share index!")
            }

            let share = &e_shares.0[i] - e_i;
            let r_share = &share * &G;

            if !e_shares.1[i].verify(&r_share) {
                return Err("Invalid recovered share!")
            }

            shares.push(share);
        }

        // recovered the key-pair for this peer
        let y_secret = shares.iter().fold(Scalar::zero(), |total, share| total +  share.yi);
        let y_public = e_shares.2;
        info!("KEY-PAIR (yi*G = {:?}, Y = {:?})", (&y_secret * &G).encode(), y_public.encode());

        // TODO: should insert a key evolution and key pair in the DB (LocalStore / GlobalStore)
        self.evidence = Some(mkey);

        /* TODO: how to to evolve all existing pseudonyms?
            * This is an issue, because the pseudonyms are not in the federated network!
            * Contact each p-server to update (delivering the evolution-key)?
            * Or, mantain the respective master-key (base-point) for each Profile?
        */

        //TODO: should return the new public-key
        Ok(())
    }

    fn derive_encryption_keys(&self, session: &str) -> EncryptionKeys {
        let n = self.config.peers.len();

        let mut e_keys = Vec::<Scalar>::with_capacity(n);
        for peer in self.config.peers.iter() {
            // perform a Diffie-Hellman between local and peer
            let dh = (&self.config.secret * &peer.pkey).compress();

            // derive secret key between peers
            let mut hasher = Sha512::new();
            hasher.input(dh.as_bytes());
            hasher.input(session.as_bytes());
            let p = Scalar::from_hash(hasher);

            e_keys.push(p);
        }

        EncryptionKeys(e_keys)
    }

    fn derive_encrypted_shares(&self, e_keys: &EncryptionKeys) -> (Vec<Share>, RistrettoPolynomial) {
        let n = self.config.peers.len();

        // derive secret polynomial and shares
        let y = rnd_scalar();
        let ak = Polynomial::rnd(y, self.config.threshold);
        let sv = ak.shares(n);

        // commit with Feldman's Coefficients
        let fk = &ak * &G;

        // encrypted shares
        let mut e_shares = Vec::<Share>::with_capacity(n);
        for i in 0..n {
            e_shares.push( &sv.0[i] + &e_keys.0[i] );
        }

        (e_shares, fk)
    } // (sv: ShareVector) containing secrets will be cleared here
}

struct EncryptionKeys(Vec<Scalar>);

impl Drop for EncryptionKeys {
    fn drop(&mut self) {
        for item in self.0.iter_mut() {
            item.clear();
        }
    }
}