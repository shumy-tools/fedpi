use std::fmt::{Debug, Formatter};

use crate::{Result, Scalar, RistrettoPoint};
use crate::shares::{Share, RistrettoPolynomial};
use crate::signatures::{IndSignature, ExtSignature};

use serde::{Serialize, Deserialize};

//--------------------------------------------------------------------
// Request MasterKey negotiation
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKeyRequest {
    pub session: String,
    pub sig: ExtSignature
}

impl MasterKeyRequest {
    pub fn sign(session: &str, admin_secret: &Scalar, admin_key: RistrettoPoint) -> Self {
        let data = Self::data(session);
        Self {
            session: session.into(),
            sig: ExtSignature::sign(admin_secret, admin_key, &data)
        }
    }

    pub fn verify(&self) -> bool {
        let data = Self::data(&self.session);
        self.sig.verify(&data)
    }

    fn data(session: &str) -> [Vec<u8>; 1] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_session = bincode::serialize(session).unwrap();
        
        [b_session]
    }
}

//--------------------------------------------------------------------
// Response to MasterKey negotiation
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct MasterKeyVote {
    pub session: String,
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
            .field("peers", &peers)
            .field("shares", &self.shares)
            .field("pkeys", &self.pkeys)
            .field("commit", &self.commit)
            .field("sig", &self.sig)
            .finish()
    }
}

impl MasterKeyVote {
    pub fn sign(session: &str, peers: &[u8], shares: Vec<Share>, pkeys: Vec<RistrettoPoint>, commit: RistrettoPolynomial, secret: &Scalar, key: &RistrettoPoint, index: usize) -> Self {
        let data = Self::data(session, peers, &shares, &pkeys, &commit);
        Self {
            session: session.into(),
            peers: peers.to_vec(),

            shares: shares,
            pkeys: pkeys,
            commit: commit,

            sig: IndSignature::sign(index, secret, key, &data)
        }
    }

    pub fn check(&self, session: &str, peers: &[u8], n: usize, pkey: &RistrettoPoint) -> Result<()> {
        if self.session != session {
            return Err("KeyResponse, expected the same session!")
        }

        if self.shares.len() != n || self.pkeys.len() != n {
            return Err("KeyResponse, expected vectors with the same lenght (shares, pkeys)!")
        }

        if self.peers != peers {
            return Err("KeyResponse, expected the same peers!")
        }

        if !self.verify(pkey) {
            return Err("KeyResponse with invalid signature!")
        }

        // it's assured that all vectors are of the same size
        // verify each encrypted share
        use crate::G;
        #[allow(non_snake_case)]
        for i in 0..n {
            // (e_i * G - P_i) -> Y_i
            let Yi = &(&self.shares[i] * &G) - &self.pkeys[i];
            if !self.commit.verify(&Yi) {
                return Err("KeyResponse with invalid shares!")
            }
        }

        Ok(())
    }

    fn verify(&self, pkey: &RistrettoPoint) -> bool {
        let data = Self::data(&self.session, &self.peers, &self.shares, &self.pkeys, &self.commit);
        self.sig.verify(pkey, &data)
    }

    fn data(session: &str, peers: &[u8], shares: &[Share], pkeys: &[RistrettoPoint], commit: &RistrettoPolynomial) -> [Vec<u8>; 5] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_session = bincode::serialize(session).unwrap();
        let b_peers = bincode::serialize(peers).unwrap();
        let b_shares = bincode::serialize(shares).unwrap();
        let b_pkeys = bincode::serialize(pkeys).unwrap();
        let b_commit = bincode::serialize(commit).unwrap();

        [b_session, b_peers, b_shares, b_pkeys, b_commit]
    }
}


//--------------------------------------------------------------------
// Commit the master key negotiation
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKey {
    pub session: String,
    pub matrix: PublicMatrix,
    pub votes: Vec<MasterKeyCompressedVote>,
    pub sig: ExtSignature,       //signature from admin
    #[serde(skip)] _phantom: () // force use of constructor
}

impl MasterKey {
    pub fn sign(session: &str, peers: &[u8], votes: Vec<MasterKeyVote>, n: usize, pkeys: &[RistrettoPoint], admin_secret: &Scalar, admin_key: RistrettoPoint) -> Result<Self> {
        // expecting responses from all peers
        if votes.len() != n {
            return Err("Expecting responses from all peers!")
        }

        // check all peer responses
        for item in votes.iter() {
            let key = pkeys.get(item.sig.index).ok_or("MasterKey, expecting to find a peer at index!")?;
            item.check(session, peers, n, key)?;
        }

        let matrix = PublicMatrix::create(&votes)?;
        let votes: Vec<MasterKeyCompressedVote> = votes.into_iter()
            .map(|vote| MasterKeyCompressedVote { shares: vote.shares, commit: vote.commit, sig: vote.sig }).collect();

        let data = Self::data(session, &matrix, &votes);
        Ok(Self {
            session: session.into(),
            matrix: matrix,
            votes: votes,
            sig: ExtSignature::sign(admin_secret, admin_key, &data),
            _phantom: ()
        })
    }

    pub fn check(&self, peers: &[u8], n: usize, pkeys: &[RistrettoPoint]) -> Result<()> {
        if self.votes.len() != n {
            return Err("Expecting votes from all peers!")
        }

        if !self.verify() {
            return Err("MasterKey with invalid signature!")
        }

        // check matrix bounds before use
        self.matrix.check(n)?;

        // reconstruct each KeyResponse and check
        for i in 0..n {
            let item = &self.votes[i];

            let resp = MasterKeyVote {
                session: self.session.clone(),
                peers: peers.to_vec(),
                
                shares: item.shares.clone(),
                pkeys: self.matrix.expand(n, i),
                commit: item.commit.clone(),

                sig: item.sig.clone()
            };

            let key = pkeys.get(item.sig.index).ok_or("MasterKey, expecting to find a peer at index!")?;
            resp.check(&self.session, peers, n, key)?;
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

    fn verify(&self) -> bool {
        let data = Self::data(&self.session, &self.matrix, &self.votes);
        self.sig.verify(&data)
    }

    fn data(session: &str, matrix: &PublicMatrix, votes: &[MasterKeyCompressedVote]) -> [Vec<u8>; 3] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_session = bincode::serialize(session).unwrap();
        let b_matrix = bincode::serialize(matrix).unwrap();
        let b_votes = bincode::serialize(votes).unwrap();

        [b_session, b_matrix, b_votes]
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKeyCompressedVote {
    pub shares: Vec<Share>,
    pub commit: RistrettoPolynomial,
    pub sig: IndSignature
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
                    return Err("Expecting a symmetric public-matrix!")
                }

                if j >= i {
                    line.push(res[i].pkeys[j]);
                }
            }

            matrix.push(line);
        }

        Ok(Self { triangle: matrix })
    }

    fn check(&self, length: usize) -> Result<()> {
        if self.triangle.len() != length {
            return Err("MasterKey matrix of incorrect size!")
        }

        // check if it's a triangular matrix
        for i in 0..length {
            if self.triangle[i].len() != length - i {
                return Err("MasterKey matrix with incorrect triangle!")
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