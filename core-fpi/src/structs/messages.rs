use crate::Result;
use crate::structs::consents::*;
use crate::structs::disclosures::*;
use crate::structs::ids::*;
use crate::structs::records::*;
use crate::structs::keys::*;

use log::error;
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};

pub fn decode<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T> {
    let msg: T = deserialize(data).map_err(|err| {
        error!("{:?} - {:?}", "Unable to decode structure!", err);
        "Unable to decode structure!"
    })?;

    Ok(msg)
}

pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    let data = serialize(msg).map_err(|err| {
        error!("{:?} - {:?}", "Unable to encode structure!", err);
        "Unable to encode structure!"
    })?;
    
    Ok(data)
}

/*
-----------------------------------------------
                Message Hierarchy
-----------------------------------------------
|     Request     |   Response   |   Commit   |
-----------------------------------------------
|    Negotiate    |     Vote     |   Evidence |
|      Query      |    QResult   |      X     |
|        X        |       X      |    Value   |
|        X        |    Notify    |      X     |
|  Publish/Send   |       X      |      X     |
-----------------------------------------------
*/

//--------------------------------------------------------------------
// Request
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    Negotiate(Negotiate),
    Query(Query)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Negotiate {
    NMasterKeyRequest(MasterKeyRequest)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Query {
    QDiscloseRequest(DiscloseRequest)
}

//--------------------------------------------------------------------
// Response
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Response {
    Vote(Vote),
    QResult(QResult)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Vote {
    VMasterKeyVote(MasterKeyVote)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum QResult {
    QDiscloseResult(DiscloseResult)
}

//--------------------------------------------------------------------
// Commit
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Commit {
    Evidence(Evidence),
    Value(Value)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Evidence {
    EMasterKey(MasterKey)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Value {
    VSubject(Subject),
    VConsent(Consent),
    VRevokeConsent(RevokeConsent),

    VNewRecord(NewRecord)
}