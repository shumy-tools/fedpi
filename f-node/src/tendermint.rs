use core_fpi::Result;

use log::{info, error};
use abci::*;

use crate::processor::Processor;

fn convert(tx: &[u8]) -> Result<Vec<u8>> {
    bs58::decode(tx).into_vec().map_err(|_| "Unable to decode base58 input!")
}

pub struct NodeApp {
    pub processor: Processor
}

impl abci::Application for NodeApp {
    fn check_tx(&mut self, req: &RequestCheckTx) -> ResponseCheckTx {        
        let tx = req.get_tx();
        info!("CheckTx-Input - {}", String::from_utf8_lossy(tx));

        let msg = match convert(tx) {
            Ok(value) => value,
            Err(err) => {
                error!("CheckTx ({:?})", err);
                let mut resp = ResponseCheckTx::new();
                resp.set_code(1);
                resp.set_log(err.into());
                return resp
            }
        };

        let mut resp = ResponseCheckTx::new();
        if let Err(err) = self.processor.validate(&msg) {
            error!("CheckTx ({:?})", err);
            resp.set_code(1);
            resp.set_log(err.into());
        }
        
        resp
    }

    fn deliver_tx(&mut self, req: &RequestDeliverTx) -> ResponseDeliverTx {
        let tx = req.get_tx();
        info!("DeliverTx-Input - {}", String::from_utf8_lossy(tx));

        let msg = match convert(tx) {
            Ok(value) => value,
            Err(err) => {
                error!("DeliverTx ({:?})", err);
                let mut resp = ResponseDeliverTx::new();
                resp.set_code(1);
                resp.set_log(err.into());
                return resp
            }
        };
        
        let mut resp = ResponseDeliverTx::new();
        if let Err(err) = self.processor.commit(&msg) {
            // The tx should have been rejected by the mempool, but may have been included in a block by a Byzantine proposer!
            error!("DeliverTx ({:?})", err);
            resp.set_code(1);
            resp.set_log(err.into());
        }

        resp
    }

    // Commit the block with the latest state from the application.
    /*fn commit(&mut self, _req: &RequestCommit) -> ResponseCommit {
        let mut resp = ResponseCommit::new();
        // Convert count to bits
        let mut buf = [0; 8];
        BigEndian::write_u64(&mut buf, self.count);
        // Set data so last state is included in the block
        
        resp.set_data(buf.to_vec());
        resp
    }*/
}