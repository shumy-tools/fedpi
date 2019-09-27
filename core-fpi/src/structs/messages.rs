use crate::Result;
use crate::structs::ids::*;
use crate::structs::records::*;
use crate::structs::keys::*;

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

/*
-----------------------------------------------
                Message Hierarchy
-----------------------------------------------
|     Request     |   Response   |   Commit   |
-----------------------------------------------
|    Negotiate    |     Vote     |   Evidence |
|      Query      |    Result    |      X     |
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
    Negotiate(Negotiate)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Negotiate {
    NMasterKeyRequest(MasterKeyRequest)
}

//--------------------------------------------------------------------
// Response
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Response {
    Vote(Vote)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Vote {
    VMasterKeyVote(MasterKeyVote)
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
    VNewRecord(NewRecord)
}