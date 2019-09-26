use std::fmt::{Debug, Formatter};

use crate::{Result, KeyEncoder, Scalar, RistrettoPoint};
use crate::shares::{Share, RistrettoPolynomial};
use crate::signatures::{IndSignature, ExtSignature};

use serde::{Serialize, Deserialize};

//--------------------------------------------------------------------
// Request MasterKey negotiation
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyRequest {
    pub session: String,
    pub sig: ExtSignature
}

impl KeyRequest {
    pub fn sign(session: &str, secret: &Scalar, key: RistrettoPoint) -> Self {
        let data = Self::data(session);

        Self {
            session: session.into(),
            sig: ExtSignature::sign(secret, key, &data)
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
pub struct KeyResponse {
    pub session: String,
    pub peers: Vec<RistrettoPoint>,

    // share structures with public verifiability
    pub shares: Vec<Share>,
    pub pkeys: Vec<RistrettoPoint>,
    pub commit: RistrettoPolynomial,

    pub sig: IndSignature
}

impl Debug for KeyResponse {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
        let peers: Vec<String> = self.peers.iter().map(|p| p.compress().encode()).collect();
        fmt.debug_struct("KeyResponse")
            .field("session", &self.session)
            .field("peers", &peers)
            .field("shares", &self.shares)
            .field("pkeys", &self.pkeys)
            .field("commit", &self.commit)
            .field("sig", &self.sig)
            .finish()
    }
}

impl KeyResponse {
    pub fn sign(session: &str, peers: Vec<RistrettoPoint>, shares: Vec<Share>, pkeys: Vec<RistrettoPoint>, commit: RistrettoPolynomial, secret: &Scalar, key: &RistrettoPoint) -> Self {
        let index = peers.iter().position(|item| item == key)
            .expect("Bug in code! Expecting to find the peer key!");
        
        let data = Self::data(session, &peers, &shares, &pkeys, &commit);

        Self {
            session: session.into(),
            peers: peers,

            shares: shares,
            pkeys: pkeys,
            commit: commit,

            sig: IndSignature::sign(index, secret, key, &data)
        }
    }

    pub fn verify(&self) -> bool {
        let pkey = self.peers.get(self.sig.index);
        if let None = pkey {
            // No key found at index, signature is invalid!
            return false
        }
        
        let data = Self::data(&self.session, &self.peers, &self.shares, &self.pkeys, &self.commit);
        self.sig.verify(&pkey.unwrap(), &data)
    }

    pub fn check(&self, session: &str, peers: &[RistrettoPoint]) -> Result<()> {
        let n = peers.len();

        if self.session != session {
            return Err("KeyResponse, expected the same session!")
        }

        if self.peers.len() != n || self.shares.len() != n || self.pkeys.len() != n {
            return Err("KeyResponse, expected vectors with the same lenght (peers, shares, pkeys)!")
        }

        if self.peers != peers {
            return Err("KeyResponse, expected the same peers!")
        }

        if !self.verify() {
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

    fn data(session: &str, peers: &[RistrettoPoint], shares: &[Share], pkeys: &[RistrettoPoint], commit: &RistrettoPolynomial) -> [Vec<u8>; 5] {
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
    pub votes: Vec<MasterKeyVote>,
    #[serde(skip)] _phantom: () // force use of constructor
}

impl MasterKey {
    pub fn create(session: &str, peers: &[RistrettoPoint], results: Vec<KeyResponse>) -> Result<Self> {
        // expecting responses from all peers
        if results.len() != peers.len() {
            return Err("Expecting responses from all peers!")
        }

        // check all peer responses
        for item in results.iter() {
            item.check(session, peers)?;
        }

        let matrix = PublicMatrix::create(&results)?;
        let votes = results.into_iter().map(|r| MasterKeyVote { shares: r.shares, commit: r.commit, sig: r.sig } ).collect();

        Ok(Self { session: session.into(), matrix: matrix, votes: votes, _phantom: () })
    }

    pub fn check(&self, peers: &[RistrettoPoint]) -> Result<()> {
        let n = peers.len();
        if self.votes.len() != n {
            return Err("Expecting votes from all peers!")
        }

        // check matrix bounds before use
        self.matrix.check(n)?;

        // reconstruct each KeyResponse and check
        // TODO: optimize to avoid clones!
        for i in 0..n {
            let item = &self.votes[i];

            let resp = KeyResponse {
                session: self.session.clone(),
                peers: peers.to_vec(),
                
                shares: item.shares.clone(),
                pkeys: self.matrix.expand(n, i),
                commit: item.commit.clone(),

                sig: item.sig.clone()
            };

            resp.check(&self.session, peers)?;
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKeyVote {
    pub shares: Vec<Share>,
    pub commit: RistrettoPolynomial,
    pub sig: IndSignature
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicMatrix {
    pub triangle: Vec<Vec<RistrettoPoint>>
}

impl PublicMatrix {
    fn create(res: &[KeyResponse]) -> Result<Self> {
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