use crate::{Result, Scalar, RistrettoPoint, CompressedRistretto};
use crate::shares::{Share, RistrettoPolynomial};
use crate::structs::ids::Subject;
use crate::structs::records::Record;
use crate::signatures::{IndSignature, ExtSignature};

use log::error;
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};


pub fn decode<'a, T: Sized + Deserialize<'a>>(data: &'a [u8]) -> Result<T> {
    let msg: T = deserialize(data).map_err(|err| {
        error!("{:?} - {:?}", "Unable to decode message!", err);
        "Unable to decode message!"
    })?;

    Ok(msg)
}

pub fn encode<T: Sized + Serialize>(msg: &T) -> Result<Vec<u8>> {
    let data = serialize(msg).map_err(|err| {
        error!("{:?} - {:?}", "Unable to encode message!", err);
        "Unable to encode message!"
    })?;
    
    Ok(data)
}

//--------------------------------------------------------------------
// Transactions
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Transaction {
    SyncSubject (Subject),
    CreateRecord (NewRecord)
}

//--------------------------------------------------------------------
// Queries
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    NegotiateMasterKey (KeyRequest)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Response {
    NegotiateMasterKey (KeyResponse)
}


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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyResponse {
    pub session: String,
    pub peers: Vec<RistrettoPoint>,
    pub shares: Vec<Share>,
    pub commit: RistrettoPolynomial,

    pub sig: IndSignature
}

impl KeyResponse {
    pub fn sign(session: &str, peers: Vec<RistrettoPoint>, shares: Vec<Share>, commit: RistrettoPolynomial, secret: &Scalar, key: &RistrettoPoint) -> Self {
        let index = peers.iter().position(|item| item == key)
            .expect("Bug in code! Expecting to find the peer key!");
        
        let data = Self::data(session, &peers, &shares, &commit);

        Self {
            session: session.into(),
            peers: peers,
            shares: shares,
            commit: commit,
            sig: IndSignature::sign(index, secret, key, &data)
        }
    }

    pub fn verify(&self) -> bool {
        let pkey: RistrettoPoint = self.peers[self.sig.index];
        
        let data = Self::data(&self.session, &self.peers, &self.shares, &self.commit);
        self.sig.verify(&pkey, &data)
    }

    fn data(session: &str, peers: &Vec<RistrettoPoint>, shares: &Vec<Share>, commit: &RistrettoPolynomial) -> [Vec<u8>; 4] {
        // These unwrap() should never fail, or it's a serious code bug!
        let b_session = bincode::serialize(session).unwrap();
        let b_peers = bincode::serialize(peers).unwrap();
        let b_shares = bincode::serialize(shares).unwrap();
        let b_commit = bincode::serialize(commit).unwrap();

        [b_session, b_peers, b_shares, b_commit]
    }
}

//--------------------------------------------------------------------
// NewRecord
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewRecord {
    pub record: Record,
    pub key: CompressedRistretto,
    pub base: CompressedRistretto
}