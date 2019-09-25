use crate::{Result, CompressedRistretto};
use crate::structs::ids::Subject;
use crate::structs::records::Record;
use crate::signatures::ExtSignature;

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
    NegotiateMasterKey (Negotiation)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Response {

}


//--------------------------------------------------------------------
// Help Structures
//--------------------------------------------------------------------
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Negotiation {
    pub session: String,
    pub auth: ExtSignature
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewRecord {
    pub record: Record,
    pub key: CompressedRistretto,
    pub base: CompressedRistretto
}