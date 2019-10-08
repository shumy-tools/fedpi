use core_fpi::Result;

use log::{error, info};
use abci::*;

use crate::processor::Processor;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn convert(tx: &[u8]) -> Result<Vec<u8>> {
    bs58::decode(tx).into_vec().map_err(|_| "Unable to decode base58 input!".into())
}

pub struct NodeApp {
    pub height: i64,
    pub processor: Processor
}

impl abci::Application for NodeApp {
    fn query(&mut self, req: &RequestQuery) -> ResponseQuery {
        let mut resp = ResponseQuery::new();

        let msg = match convert(&req.data) {
            Ok(value) => value,
            Err(err) => {
                error!("Query-Error: {:?}", err);
                resp.set_code(1);
                resp.set_log(err.into());
                return resp
            }
        };

        match self.processor.request(&msg) {
            Ok(data) => resp.set_value(data),
            Err(err) => {
                error!("Query-Error: {:?}", err);
                resp.set_code(1);
                resp.set_log(err.into());
            }
        }
        
        resp
    }

    fn check_tx(&mut self, req: &RequestCheckTx) -> ResponseCheckTx {        
        let tx = req.get_tx();
        let mut resp = ResponseCheckTx::new();

        let msg = match convert(tx) {
            Ok(value) => value,
            Err(err) => {
                error!("CheckTx-Error: {:?}", err);
                resp.set_code(1);
                resp.set_log(err.into());
                return resp
            }
        };

        if let Err(err) = self.processor.filter(&msg) {
            error!("CheckTx-Error: {:?}", err);
            resp.set_code(1);
            resp.set_log(err.into());
        }
        
        resp
    }

    fn deliver_tx(&mut self, req: &RequestDeliverTx) -> ResponseDeliverTx {
        let tx = req.get_tx();
        let mut resp = ResponseDeliverTx::new();

        let msg = match convert(tx) {
            Ok(value) => value,
            Err(err) => {
                error!("DeliverTx-Error: {:?}", err);
                resp.set_code(1);
                resp.set_log(err.into());
                return resp
            }
        };

        if let Err(err) = self.processor.deliver(&msg) {
            // The tx should have been rejected by the mempool, but may have been included in a block by a Byzantine proposer!
            error!("DeliverTx-Error: {:?}", err);
            resp.set_code(1);
            resp.set_log(err.into());
        }

        resp
    }

    fn begin_block(&mut self, _req: &RequestBeginBlock) -> ResponseBeginBlock {
        self.processor.start();
        ResponseBeginBlock::new()
    }

    fn end_block(&mut self, req: &RequestEndBlock) -> ResponseEndBlock {
        self.height = req.height;
        ResponseEndBlock::new()
    }

    fn commit(&mut self, _req: &RequestCommit) -> ResponseCommit {
        let state = self.processor.commit(self.height);
        
        let mut resp = ResponseCommit::new();
        resp.set_data(state.hash);
        resp
    }

    fn info(&mut self, _req: &RequestInfo) -> ResponseInfo {
        let mut resp = ResponseInfo::new();
        resp.set_data("FedPI Node".into());
        resp.set_version(VERSION.into());

        let state = self.processor.state();
        info!("INFO - (ver = {:?}, height = {:?}, hash = {:?})", VERSION, state.height, bs58::encode(&state.hash).into_string());
        
        resp.set_last_block_height(state.height);
        resp.set_last_block_app_hash(state.hash);
        resp
    }
}