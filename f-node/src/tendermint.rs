use abci::*;
use log::info;

pub struct NodeApp;

impl abci::Application for NodeApp {
    fn check_tx(&mut self, req: &RequestCheckTx) -> ResponseCheckTx {
        let tx = req.get_tx();
        let value = String::from_utf8_lossy(tx);

        info!("VALUE = {:?}", value);

        let resp = ResponseCheckTx::new();
        resp
    }

    fn deliver_tx(&mut self, req: &RequestDeliverTx) -> ResponseDeliverTx {
        ResponseDeliverTx::new()
    }

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