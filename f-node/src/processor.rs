use crate::Result;

use log::info;
use core_fpi::messages::*;
use core_fpi::messages::Message::*;

pub struct Processor {}

impl Processor {
    pub fn validate(&self, data: &[u8]) -> Result<()> {
        let msg = decode(data)?;
        match msg {
            SyncSubject(subject) => info!("SyncSubject - {:#?}", subject),
            CreateRecord{ record, key, base } => info!("CreateRecord - {:#?}", record)
        };

        //let value = String::from_utf8_lossy(msg);
        //info!("VALUE = {:?}", value);

        Ok(())
    }

    pub fn commit(&self, data: &[u8]) -> Result<()> {
        //let msg = decode(data)?;

        Ok(())
    }
}