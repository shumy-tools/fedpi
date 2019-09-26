use crate::Result;
use crate::structs::ids::*;
use crate::structs::records::*;
use crate::negotiation::*;

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
    CreateRecord (NewRecord),
    CommitKey (MasterKey)
}

//--------------------------------------------------------------------
// Queries
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    NegotiateKey (KeyRequest)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Response {
    NegotiateKey (KeyResponse)
}