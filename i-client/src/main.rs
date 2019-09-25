#[forbid(unsafe_code)]

use std::io::{Error, ErrorKind};
use clap::{Arg, App, SubCommand};

use serde::Deserialize;

mod manager;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let matches = App::new("FedPI Node")
        .version(VERSION)
        .about("The official FedPI CLI implementation.")
        .author("Micael Pedrosa <micaelpedrosa@ua.pt>")
        .arg(Arg::with_name("host")
            .help("Set the host:port for the request")
            .required(true)
            .long("host")
            .takes_value(true))
        .arg(Arg::with_name("sid")
            .help("Select the subject-id and respective store")
            .required(true)
            .long("sid")
            .takes_value(true))
        .subcommand(SubCommand::with_name("reset")
            .about("View local subject data"))
        .subcommand(SubCommand::with_name("view")
            .about("View local subject data"))
        .subcommand(SubCommand::with_name("create")
            .about("Request the creation of a subject"))
        .subcommand(SubCommand::with_name("evolve")
            .about("Request the evolution of the subject key"))
        .subcommand(SubCommand::with_name("profile")
            .about("Request the creation or evolution of the subject profile")
            .arg(Arg::with_name("type")
                .help("Select the profile type")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("lurl")
                .help("Selects the profile location URL")
                .takes_value(true)
                .required(true)))
        .get_matches();
    
    let host = matches.value_of("host").unwrap().to_owned();
    let sid = matches.value_of("sid").unwrap().to_owned();

    let mut sm = manager::SubjectManager::new(&sid, |msg| {
        let msg_data = core_fpi::messages::encode(&msg).map_err(|_| Error::new(ErrorKind::Other, "Unable to encode message!"))?;
        let data = bs58::encode(&msg_data).into_string();

        let url = format!("http://{}/broadcast_tx_commit?tx={:?}", host, data);
        
        let mut resp = reqwest::get(url.as_str()).map_err(|_| Error::new(ErrorKind::Other, "Unable to sync with network!"))?;
        let value: TxResult = resp.json().map_err(|e| Error::new(ErrorKind::Other, format!("Unable to parse JSON - {:?}", e)))?;

        println!("{:#?}", value);        
        if value.result.check_tx.code != 0 || value.result.deliver_tx.code != 0 {
            return Err(Error::new(ErrorKind::Other, "Tx error from network!"))
        }

        Ok(())
    });

    // http://localhost:26660/abci_query?data="IHAVENOIDEA"

    if matches.is_present("reset") {
        println!("Reseting {:?}", sid);
        sm.reset();
    } else if matches.is_present("view") {
        println!("{:#?}", sm.sto);
    } else if matches.is_present("create") {
        sm.create().unwrap();
    } else if matches.is_present("evolve") {
        sm.evolve().unwrap();
    } else if matches.is_present("profile") {
        let matches = matches.subcommand_matches("profile").unwrap();
        let typ = matches.value_of("type").unwrap().to_owned();
        let lurl = matches.value_of("lurl").unwrap().to_owned();
        sm.profile(&typ, &lurl).unwrap();
    } else {
        let url = format!("http://{}/status", host);
        
        println!("GET {}", url);
        let resp = reqwest::get(url.as_str()).unwrap();
        println!("{:#?}", resp);
    }
}

#[derive(Deserialize, Debug)]
struct TxResult {
    jsonrpc: String,
    id: String,
    result: TxResultBody
}

#[derive(Deserialize, Debug)]
struct TxResultBody {
    check_tx: CheckTxResult,
    deliver_tx: DeliverTxResult,
    hash: String,
    height: String
}

#[derive(Deserialize, Debug)]
struct CheckTxResult {
    code: i32,
    data: Option<String>,
    log: String,
    info: String
}

#[derive(Deserialize, Debug)]
struct DeliverTxResult {
    code: i32,
    data: Option<String>,
    log: String,
    info: String
}

/*
{
  "jsonrpc": "2.0",
  "id": "",
  "result": {
    "check_tx": {
      "code": 1,
      "data": null,
      "log": "Incorrect index for new subject-key!",
      "info": "",
      "gasWanted": "0",
      "gasUsed": "0",
      "events": [],
      "codespace": ""
    },
    "deliver_tx": {
      "code": 0,
      "data": null,
      "log": "",
      "info": "",
      "gasWanted": "0",
      "gasUsed": "0",
      "events": [],
      "codespace": ""
    },
    "hash": "8F58D768B119FF81A71B19092E8575A867CCCED7E7A09613629E65436443E88B",
    "height": "0"
  }
}
*/