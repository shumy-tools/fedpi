use std::fmt::{Debug, Formatter};
use std::time::Duration;

use crate::ids::*;
use crate::structs::*;
use crate::{Result, Scalar, RistrettoPoint};
use crate::shares::{Share, RistrettoPolynomial, Degree};
use crate::signatures::IndSignature;

use serde::{Serialize, Deserialize};

//--------------------------------------------------------------------
// Request MasterKey negotiation
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKeyRequest {
    pub sid: String,
    pub kid: String,
    pub peers: Vec<u8>,
    pub sig: IndSignature
}

impl Constraints for MasterKeyRequest {
    fn sid(&self) -> &str { &self.sid }

    fn verify(&self, subject: &Subject, threshold: Duration) -> Result<()> {
        if self.sid.len() > MAX_SUBJECT_ID_SIZE {
            return Err(format!("Field Constraint - (sid, max-size = {})", MAX_SUBJECT_ID_SIZE))
        }

        if self.kid.len() > MAX_KEY_ID_SIZE {
            return Err(format!("Field Constraint - (kid, max-size = {})", MAX_KEY_ID_SIZE))
        }

        if self.peers.len() > MAX_HASH_SIZE {
            return Err(format!("Field Constraint - (peers, max-size = {})", MAX_HASH_SIZE))
        }

        if !self.sig.sig.check_timestamp(threshold) {
            return Err("Field Constraint - (sig, Timestamp out of valid range)".into())
        }

        let skey = subject.keys.last().ok_or("No active subject-key found!")?;
        let sig_data = Self::data(&self.sid, &self.kid, &self.peers);
        if !self.sig.verify(&skey.key, &sig_data) {
            return Err("Field Constraint - (sig, Invalid signature)".into())
        }

        Ok(())
    }
}

impl MasterKeyRequest {
    pub fn sign(sid: &str, kid: &str, peers: &[u8], sig_s: &Scalar, sig_key: &SubjectKey) -> Self {
        let sig_data = Self::data(sid, kid, peers);
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, &sig_data); 
        
        Self { sid: sid.into(), kid: kid.into(), peers: peers.to_vec(), sig }
    }

    pub fn check(&self, peers_hash: &[u8]) -> Result<()> {
        if self.peers != peers_hash {
            return Err("Field Constraint - (peers, Incorrect peers-hash)".into())
        }

        Ok(())
    }

    fn data(sid: &str, kid: &str, peers: &[u8]) -> [Vec<u8>; 3] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_sid = bincode::serialize(sid).unwrap();
        let b_kid = bincode::serialize(kid).unwrap();
        let b_peers = bincode::serialize(peers).unwrap();
        
        [b_sid, b_kid, b_peers]
    }
}

//--------------------------------------------------------------------
// Response to MasterKey negotiation
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct MasterKeyVote {
    pub session: String,
    pub kid: String,
    pub peers: Vec<u8>,

    // share structures with public verifiability
    pub shares: Vec<Share>,
    pub pkeys: Vec<RistrettoPoint>,
    pub commit: RistrettoPolynomial,

    pub sig: IndSignature
}

impl Debug for MasterKeyVote {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        let peers = bs58::encode(&self.peers).into_string();
        fmt.debug_struct("MasterKeyVote")
            .field("session", &self.session)
            .field("kid", &self.kid)
            .field("peers", &peers)
            .field("shares", &self.shares)
            .field("pkeys", &self.pkeys)
            .field("commit", &self.commit)
            .field("sig", &self.sig)
            .finish()
    }
}

impl MasterKeyVote {
    pub fn sign(session: &str, kid: &str, peers_hash: &[u8], shares: Vec<Share>, pkeys: Vec<RistrettoPoint>, commit: RistrettoPolynomial, secret: &Scalar, key: &RistrettoPoint, index: usize) -> Self {
        let sig_data = Self::data(session, kid, peers_hash, &shares, &pkeys, &commit);
        let sig = IndSignature::sign(index, secret, key, &sig_data);

        Self { session: session.into(), kid: kid.into(), peers: peers_hash.to_vec(), shares, pkeys, commit, sig }
    }

    pub fn check(&self, session: &str, kid: &str, peers_hash: &[u8], n: usize, pkey: &RistrettoPoint) -> Result<()> {
        /*if !self.sig.sig.check_timestamp(threshold) {
            return Err("Timestamp out of valid range!".into())
        }*/

        if self.session != session {
            return Err("Field Constraint - (session, Expected the same session)".into())
        }

        if self.kid != kid {
            return Err("Field Constraint - (kid, Expected the same key-id)".into())
        }

        if self.peers != peers_hash {
            return Err("Field Constraint - (peers, Incorrect peers-hash)".into())
        }

        if self.shares.len() != n || self.pkeys.len() != n {
            return Err("Field Constraint - (shares/pkeys, Expected vectors with the correct lenght)".into())
        }

        if self.commit.degree() != n + 1 {
            return Err("Field Constraint - (commit, Incorrect polynomial degree)".into())
        }

        let sig_data = Self::data(&self.session, &self.kid, &self.peers, &self.shares, &self.pkeys, &self.commit);
        if !self.sig.verify(pkey, &sig_data) {
            return Err("Invalid master-key request signature!".into())
        }

        // it's assured that all vectors are of the same size
        // verify each encrypted share
        use crate::G;
        #[allow(non_snake_case)]
        for i in 0..n {
            // (e_i * G - P_i) -> Y_i
            let Yi = &(&self.shares[i] * &G) - &self.pkeys[i];
            if !self.commit.verify(&Yi) {
                return Err("KeyResponse with invalid shares!".into())
            }
        }

        Ok(())
    }

    fn data(session: &str, kid: &str, peers: &[u8], shares: &[Share], pkeys: &[RistrettoPoint], commit: &RistrettoPolynomial) -> [Vec<u8>; 6] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_session = bincode::serialize(session).unwrap();
        let b_kid = bincode::serialize(kid).unwrap();
        let b_peers = bincode::serialize(peers).unwrap();
        let b_shares = bincode::serialize(shares).unwrap();
        let b_pkeys = bincode::serialize(pkeys).unwrap();
        let b_commit = bincode::serialize(commit).unwrap();

        [b_session, b_kid, b_peers, b_shares, b_pkeys, b_commit]
    }
}


//--------------------------------------------------------------------
// Commit the master key negotiation
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKey {
    pub sid: String,
    pub session: String,
    pub kid: String,
    pub matrix: PublicMatrix,
    pub votes: Vec<MasterKeyCompressedVote>,
    
    pub sig: IndSignature,       //signature from admin
    #[serde(skip)] _phantom: () // force use of constructor
}

impl Constraints for MasterKey {
    fn sid(&self) -> &str { &self.sid }

    fn verify(&self, subject: &Subject, threshold: Duration) -> Result<()> {
        if self.sid.len() > MAX_SUBJECT_ID_SIZE {
            return Err(format!("Field Constraint - (sid, max-size = {})", MAX_SUBJECT_ID_SIZE))
        }

        if self.session.len() > MAX_HASH_SIZE {
            return Err(format!("Field Constraint - (session, max-size = {})", MAX_HASH_SIZE))
        }

        if self.kid.len() > MAX_KEY_ID_SIZE {
            return Err(format!("Field Constraint - (kid, max-size = {})", MAX_KEY_ID_SIZE))
        }

        if self.matrix.triangle.len() > MAX_PEERS {
            return Err(format!("Field Constraint - (matrix, max-size = {})", MAX_PEERS))
        }

        for line in self.matrix.triangle.iter() {
            if line.len() > MAX_PEERS {
                return Err(format!("Field Constraint - (matrix-line, max-size = {})", MAX_PEERS))
            }
        }

        if self.votes.len() > MAX_PEERS {
            return Err(format!("Field Constraint - (votes, max-size = {})", MAX_PEERS))
        }

        if !self.sig.sig.check_timestamp(threshold) {
            return Err("Field Constraint - (sig, Timestamp out of valid range)".into())
        }

        let skey = subject.keys.last().ok_or("No active subject-key found!")?;
        let sig_data = Self::data(&self.sid, &self.session, &self.kid, &self.matrix, &self.votes);
        if !self.sig.verify(&skey.key, &sig_data) {
            return Err("Field Constraint - (sig, Invalid signature)".into())
        }

        Ok(())
    }
}

impl MasterKey {
    pub fn sign(sid: &str, session: &str, kid: &str, peers_hash: &[u8], votes: Vec<MasterKeyVote>, pkeys: &[RistrettoPoint], sig_s: &Scalar, sig_key: &SubjectKey) -> Result<Self> {
        let n = pkeys.len();

        // check all peer responses
        for item in votes.iter() {
            let key = pkeys.get(item.sig.index)
                .ok_or_else(|| format!("MasterKey, expecting to find a peer at index: {}", item.sig.index))?;
            item.check(session, kid, peers_hash, n, key)?;
        }

        let matrix = PublicMatrix::create(&votes)?;
        let votes: Vec<MasterKeyCompressedVote> = votes.into_iter()
            .map(|vote| MasterKeyCompressedVote { shares: vote.shares, commit: vote.commit, sig: vote.sig }).collect();

        let sig_data = Self::data(sid, session, kid, &matrix, &votes);
        let sig = IndSignature::sign(sig_key.sig.index, sig_s, &sig_key.key, &sig_data);

        Ok(Self { sid: sid.into(), session: session.into(), kid: kid.into(), matrix, votes, sig, _phantom: () })
    }

    pub fn check(&self, peers_hash: &[u8], pkeys: &[RistrettoPoint]) -> Result<()> {
        let n = pkeys.len();

        self.matrix.check(n)?;
        
        if self.votes.len() != n {
            return Err("Expecting votes from all peers!".into())
        }

        // reconstruct each KeyResponse and check
        for i in 0..n {
            let item = &self.votes[i];
            item.check(n)?;

            let resp = MasterKeyVote {
                session: self.session.clone(),
                kid: self.kid.clone(),
                peers: peers_hash.to_vec(),
                
                shares: item.shares.clone(),
                pkeys: self.matrix.expand(n, i),
                commit: item.commit.clone(),

                sig: item.sig.clone()
            };

            let key = pkeys.get(item.sig.index).ok_or("MasterKey, expecting to find a peer at index!")?;
            resp.check(&self.session, &self.kid, peers_hash, n, key)?;
        }

        Ok(())
    }

    pub fn extract(&self, index: usize) -> (Vec<Share>, Vec<RistrettoPolynomial>, RistrettoPoint) {
        let n = self.votes.len();

        // index should be confirmed before calling this
        let mut shares = Vec::<Share>::with_capacity(n);
        let mut commits = Vec::<RistrettoPolynomial>::with_capacity(n);
        let mut pkey = RistrettoPoint::default();
        for vote in self.votes.iter() {
            // collect all shares targeting this peer
            let share = vote.shares[index].clone();
            let commit = vote.commit.clone();
            
            pkey += commit.A[0];
            shares.push(share);
            commits.push(commit);
        }

        (shares, commits, pkey)
    }

    fn data(sid: &str, session: &str, kid: &str, matrix: &PublicMatrix, votes: &[MasterKeyCompressedVote]) -> [Vec<u8>; 5] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_sid = bincode::serialize(sid).unwrap();
        let b_session = bincode::serialize(session).unwrap();
        let b_kid = bincode::serialize(kid).unwrap();
        let b_matrix = bincode::serialize(matrix).unwrap();
        let b_votes = bincode::serialize(votes).unwrap();

        [b_sid, b_session, b_kid, b_matrix, b_votes]
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKeyCompressedVote {
    pub shares: Vec<Share>,
    pub commit: RistrettoPolynomial,
    pub sig: IndSignature
}

impl MasterKeyCompressedVote {
    fn check(&self, n: usize) -> Result<()> {
        if self.shares.len() != n {
            return Err("Field Constraint - (shares, Expected vector with the correct lenght)".into())
        }

        if self.commit.degree() != n + 1 {
            return Err("Field Constraint - (commit, Incorrect polynomial degree)".into())
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicMatrix {
    pub triangle: Vec<Vec<RistrettoPoint>>
}

impl PublicMatrix {
    fn create(res: &[MasterKeyVote]) -> Result<Self> {
        let n = res.len();

        let mut matrix = Vec::<Vec<RistrettoPoint>>::with_capacity(n);
        for i in 0..n {
            let mut line = Vec::<RistrettoPoint>::with_capacity(n-i);
            for j in 0..n {
                if res[i].pkeys[j] != res[j].pkeys[i] {
                    return Err("Expecting a symmetric public-matrix!".into())
                }

                if j >= i {
                    line.push(res[i].pkeys[j]);
                }
            }

            matrix.push(line);
        }

        Ok(Self { triangle: matrix })
    }

    fn check(&self, n: usize) -> Result<()> {
        if self.triangle.len() != n {
            return Err("Matrix of incorrect size!".into())
        }

        // check if it's a triangular matrix
        for i in 0..n {
            if self.triangle[i].len() != n - i {
                return Err("Matrix with incorrect triangle!".into())
            }
        }

        Ok(())
    }

    fn expand(&self, length: usize, index: usize) -> Vec<RistrettoPoint> {
        let mut pkeys = Vec::<RistrettoPoint>::with_capacity(length);
        for j in 0..index {
            // (requires [index-j] instead fo [index]). The matrix is shifted left due to the lack of items
            let replicated = self.triangle[j][index-j];
            pkeys.push(replicated);
        }

        pkeys.extend(&self.triangle[index]);
        
        /*print!("L{} {}:", length, index);
        for k in pkeys.iter() {
            print!(" {}", k.encode());
        }
        println!("");*/

        pkeys
    }
}

//--------------------------------------------------------------------
// Final result of the master-key negotiation
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKeyPair {
    pub kid: String,
    pub share: Share,
    pub public: RistrettoPoint
}