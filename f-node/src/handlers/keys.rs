use std::sync::Arc;
use log::info;
use sha2::{Sha512, Digest};
use clear_on_drop::clear::Clear;

use core_fpi::{rnd_scalar, G, Result, Scalar};
use core_fpi::shares::*;
use core_fpi::messages::*;
use core_fpi::keys::*;

use crate::config::Config;
use crate::db::*;

pub struct MasterKeyHandler {
    cfg: Arc<Config>,
    store: Arc<AppDB>
}

impl MasterKeyHandler {
    pub fn new(cfg: Arc<Config>, store: Arc<AppDB>) -> Self {
        Self { cfg, store }
    }

    pub fn request(&mut self, req: MasterKeyRequest) -> Result<Vec<u8>> {
        info!("REQUEST-KEY - (session = {:?}, kid = {:?})", req.sig.id(), req.kid);

        // check constraints
        req.check(&self.cfg.peers_hash)?;

        // verify if the subject has authorization to fire negotiation
        if req.sid != self.cfg.admin {
            return Err("Subject has not authorization to negotiate a master-key!".into())
        }

        let e_keys = self.derive_encryption_keys(&req.sig.id());        // encryption keys (e_i)
        let p_keys = e_keys.0.iter().map(|e_i| e_i * G).collect();      // public keys (e_i * G -> E_i)
        let e_shares = self.derive_encrypted_shares(&e_keys);           // encrypted shares and Feldman's Coefficients (e_i + y_i -> p_i, A_k)

        // (session, ordered peer's list, encrypted shares, Feldman's Coefficients, peer signature)
        let vote = MasterKeyVote::sign(&req.sig.id(), &req.kid, &self.cfg.peers_hash, e_shares.0, p_keys, e_shares.1, &self.cfg.secret, &self.cfg.pkey, self.cfg.index);
        let msg = Response::Vote(Vote::VMasterKeyVote(vote));

        // store local evidence
        let mkrid = mkrid(&req.sid, req.sig.id());
        self.store.set_local(&mkrid, req);

        encode(&msg)
    }

    pub fn deliver(&mut self, evidence: MasterKey) -> Result<()> {
        info!("DELIVER-KEY - (session = {:?}, #votes = {:?})", evidence.session, evidence.votes.len());
        let mkrid = mkrid(&evidence.sid, &evidence.session);
        let mkid = mkid(&evidence.kid, evidence.sig.id());
        let mkpid = mkpid(&evidence.kid);

        // ---------------transaction---------------
        let tx = self.store.tx();
            // check constraints
            evidence.check(&self.cfg.peers_hash, &self.cfg.peers_keys)?;

            if !tx.contains(&mkrid) {
                return Err("MasterKeyRequest not found!".into())
            }

            // verify if the subject has authorization to commit evidence
            if evidence.sid != self.cfg.admin {
                return Err("Subject has not authorization to commit the master-key evidence!".into())
            }

            // avoid evidence override
            if tx.contains(&mkid) {
                return Err("Master-key evidence already exists!".into())
            }
        
            let n = self.cfg.peers.len();
            let e_shares = evidence.extract(self.cfg.index);                    // encrypted shares, Feldman's Coefs and PublicKey (e_i + y_i -> p_i, A_k, Y)
            let e_keys = self.derive_encryption_keys(&evidence.session);        // encryption keys (e_i)

            if e_shares.0.len() != n || e_keys.0.len() != n {
                return Err("Incorrect sizes on MasterKey commit (#e_shares != n || #e_keys != n)!".into())
            }

            // recover an check encrypted shares
            let share_index = e_shares.0[0].i;
            let mut shares = Vec::<Share>::with_capacity(n);
            for (i, e_i) in e_keys.0.iter().enumerate() {
                if e_shares.0[i].i != share_index {
                    return Err("Invalid share index!".into())
                }

                let share = &e_shares.0[i] - e_i;
                let r_share = &share * &G;

                if !e_shares.1[i].verify(&r_share) {
                    return Err("Invalid recovered share!".into())
                }

                shares.push(share);
            }

            // recovered the key-pair for this peer
            let y_secret = shares.iter().fold(Scalar::zero(), |total, share| total +  share.yi);
            let y_public = e_shares.2;

            //info!("KEY-PAIR (yi*G = {:?}, Y = {:?})", (y_secret * G).encode(), y_public.encode());
            let pair = MasterKeyPair {
                kid: evidence.kid.clone(),
                share: Share { i: share_index, yi: y_secret },
                public: y_public
            };

            tx.set(&mkid, evidence);
            tx.set_local(&mkpid, pair);

            /* TODO: how to to evolve all existing pseudonyms?
                * This is an issue, because the pseudonyms are not in the federated network!
                * Contact each p-server to update (delivering the evolution-key)?
                * Or, mantain the respective master-key (base-point) for each Profile?
            */
        
        Ok(())
    }

    fn derive_encryption_keys(&self, session: &str) -> EncryptionKeys {
        let n = self.cfg.peers.len();

        let mut e_keys = Vec::<Scalar>::with_capacity(n);
        for peer in self.cfg.peers.iter() {
            // perform a Diffie-Hellman between local and peer
            let dh = (self.cfg.secret * peer.pkey).compress();

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
        let n = self.cfg.peers.len();

        // derive secret polynomial and shares
        let y = rnd_scalar();
        let ak = Polynomial::rnd(y, self.cfg.threshold);
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