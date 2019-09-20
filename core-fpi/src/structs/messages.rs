use curve25519_dalek::ristretto::CompressedRistretto;

use crate::Result;
use crate::structs::ids::Subject;
use crate::structs::records::Record;

use log::error;
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    SyncSubject (Subject),
    CreateRecord { record: Record, key: CompressedRistretto, base: CompressedRistretto }
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let data = serialize(self).map_err(|err| {
            error!("{:?} - {:?}", "Unable to encode message!", err);
            "Unable to encode message!"
        })?;
        
        Ok(data)
    }
}

pub fn decode(data: &[u8]) -> Result<Message> {
    let msg: Message = deserialize(data).map_err(|err| {
        error!("{:?} - {:?}", "Unable to decode message!", err);
        "Unable to decode message!"
    })?;

    Ok(msg)
}