#![forbid(unsafe_code)]

use std::io::{Result, Error, ErrorKind};
use clap::{Arg, App, SubCommand};
use core_fpi::messages::*;

use serde::Deserialize;

mod config;
mod manager;

use config::Peer;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let matches = App::new("FedPI Node")
        .version(VERSION)
        .about("The official FedPI CLI implementation.")
        .author("Micael Pedrosa <micaelpedrosa@ua.pt>")
        .arg(Arg::with_name("home")
            .help("Set the app config directory.")
            .required(false)
            .long("home")
            .takes_value(true))
        .arg(Arg::with_name("sid")
            .help("Select the subject-id and respective store")
            .required(true)
            .long("sid")
            .takes_value(true))
        .subcommand(SubCommand::with_name("reset")
            .about("Reset the local subject data"))
        .subcommand(SubCommand::with_name("view")
            .about("View the local subject data"))
        .subcommand(SubCommand::with_name("create")
            .about("Request the creation of a subject"))
        .subcommand(SubCommand::with_name("evolve")
            .about("Request the evolution of the subject-key"))
        .subcommand(SubCommand::with_name("negotiate")
            .about("Fires the negotiation protocol to create or update a master key")
            .arg(Arg::with_name("kid")
                .help("Select the key-id")
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("profile")
            .about("Request the creation or evolution of a subject profile")
            .arg(Arg::with_name("type")
                .help("Select the profile type")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("lurl")
                .help("Select the profile location")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("encrypted")
                .help("IS the profile stream encrypted?")
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("consent")
            .about("Authorize full-disclosure to another subject-id for a set of profiles")
            .arg(Arg::with_name("auth")
                .help("Authorized subject-id")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("profiles")
                .help("Selects a set of profile types")
                .min_values(1)
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("revoke")
            .about("Revoke a previous authorizations")
            .arg(Arg::with_name("auth")
                .help("Authorized subject-id")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("profiles")
                .help("Selects a set of profile types")
                .min_values(1)
                .takes_value(true)
                .required(true)))
        .subcommand(SubCommand::with_name("disclose")
            .about("Request profile disclosures for subject (requires consent)")
            .arg(Arg::with_name("target")
                .help("Select the sibject-id")
                .takes_value(true)
                .required(true))
            .arg(Arg::with_name("profiles")
                .help("Selects a set of profile types")
                .min_values(1)
                .takes_value(true)
                .required(true)))
        .get_matches();
    
    let home = matches.value_of("home").unwrap_or(".");
    let home = if home.ends_with('/') { &home[..home.len()-1] } else { home };

    // read configuration from HOME/<sid>.toml file
    let sid = matches.value_of("sid").unwrap().to_owned();
    let cfg = config::Config::new(&home, &sid);

    let tx_handler = |peer: &Peer, msg: Commit| -> Result<()> {
        let msg_data = core_fpi::messages::encode(&msg).map_err(|_| Error::new(ErrorKind::Other, "Unable to encode message!"))?;
        let data = bs58::encode(&msg_data).into_string();

        let url = format!("{}/broadcast_tx_commit?tx={:?}", peer.host, data);
        
        let mut resp = reqwest::get(url.as_str()).map_err(|_| Error::new(ErrorKind::Other, "Unable to commit to network!"))?;
        //println!("RES: {:?}", resp.text());
        let res: TxResult = resp.json().map_err(|e| Error::new(ErrorKind::Other, format!("Unable to parse JSON - {:?}", e)))?;

        if let Some(error) = res.error {
            return Err(Error::new(ErrorKind::Other, format!("Transaction {:?} from network: {}", error.message, error.data)))
        }

        let result = res.result.unwrap();

        if result.check_tx.code != 0 {
            return Err(Error::new(ErrorKind::Other, format!("Transaction error from network. On check: {}", result.check_tx.log)))
        }

        if result.deliver_tx.code != 0 {
            return Err(Error::new(ErrorKind::Other, format!("Transaction error from network. On deliver: {}", result.deliver_tx.log)))
        }

        Ok(())
    };

    let query_handler = |peer: &Peer, msg: Request| -> Result<Response> {
        let msg_data = core_fpi::messages::encode(&msg).map_err(|_| Error::new(ErrorKind::Other, "Unable to encode message!"))?;
        let data = bs58::encode(&msg_data).into_string();

        let url = format!("{}/abci_query?data={:?}", peer.host, data);

        let mut resp = reqwest::get(url.as_str()).map_err(|_| Error::new(ErrorKind::Other, "Unable to query network!"))?;
        let res: QueryResult = resp.json().map_err(|e| Error::new(ErrorKind::Other, format!("Unable to parse JSON - {:?}", e)))?;

        if res.result.response.code != 0 {
            return Err(Error::new(ErrorKind::Other, format!("Query error from network: {}", res.result.response.log)))
        }

        // expect value if code == 0
        let value = res.result.response.value.unwrap();

        let data = base64::decode(&value).map_err(|_| Error::new(ErrorKind::Other, "Unable to decode base64!"))?;
        let response: Response = core_fpi::messages::decode(data.as_ref()).map_err(|_| Error::new(ErrorKind::Other, "Unable to decode message!"))?;

        Ok(response)
    };

    // tx_handler and query_handler are tendermint adaptors. The SubjectManager is independent of the used blockchain technology.
    let mut sm = manager::SubjectManager::new(home, &sid, cfg, tx_handler, query_handler);

    if matches.is_present("reset") {
        println!("Reseting {:?}", sid);
        sm.reset();
    } else if matches.is_present("view") {
        match sm.sto {
            None => println!("No subject available"),
            Some(my) => println!("{:#?}", my)
        }
    } else if matches.is_present("create") {
        if let Err(e) = sm.create() {
            println!("ERROR -> {}", e);
        }
    } else if matches.is_present("evolve") {
        sm.evolve().unwrap();
    } else if matches.is_present("negotiate") {
        let matches = matches.subcommand_matches("negotiate").unwrap();
        let kid = matches.value_of("kid").unwrap().to_owned();

        if let Err(e) = sm.negotiate(&kid) {
            println!("ERROR -> {}", e);
        }
    } else if matches.is_present("profile") {
        let matches = matches.subcommand_matches("profile").unwrap();
        let typ = matches.value_of("type").unwrap().to_owned();
        let lurl = matches.value_of("lurl").unwrap().to_owned();
        
        let encrypted = matches.value_of("encrypted").unwrap().to_owned();
        let encrypted = encrypted.parse().unwrap();
        
        if let Err(e) = sm.profile(&typ, &lurl, encrypted) {
            println!("ERROR -> {}", e);
        }
    } else if matches.is_present("consent") {
        let matches = matches.subcommand_matches("consent").unwrap();
        let auth = matches.value_of("auth").unwrap().to_owned();
        let profiles: Vec<&str> = matches.values_of("profiles").unwrap().collect();
        let profiles: Vec<String> = profiles.iter().map(|v| v.to_string()).collect();

        if let Err(e) = sm.consent(&auth, &profiles) {
            println!("ERROR -> {}", e);
        }
    } else if matches.is_present("revoke") {
        let matches = matches.subcommand_matches("revoke").unwrap();
        let auth = matches.value_of("auth").unwrap().to_owned();
        let profiles: Vec<&str> = matches.values_of("profiles").unwrap().collect();
        let profiles: Vec<String> = profiles.iter().map(|v| v.to_string()).collect();

        if let Err(e) = sm.revoke(&auth, &profiles) {
            println!("ERROR -> {}", e);
        }
    } else if matches.is_present("disclose") {
        let matches = matches.subcommand_matches("disclose").unwrap();
        let target = matches.value_of("target").unwrap().to_owned();
        let profiles: Vec<&str> = matches.values_of("profiles").unwrap().collect();
        let profiles: Vec<String> = profiles.iter().map(|v| v.to_string()).collect();

        if let Err(e) = sm.disclose(&target, &profiles) {
            println!("ERROR -> {}", e);
        }
    }
}

#[derive(Deserialize, Debug)]
struct TxResult {
    jsonrpc: String,
    id: String,
    result: Option<TxResultOk>,
    error: Option<TxResultError>
}

#[derive(Deserialize, Debug)]
struct TxResultOk {
    check_tx: CheckTxResult,
    deliver_tx: DeliverTxResult,
    hash: String,
    height: String
}

#[derive(Deserialize, Debug)]
struct TxResultError {
    code: i32,
    message: String,
    data: String
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


#[derive(Deserialize, Debug)]
struct QueryResult {
    jsonrpc: String,
    id: String,
    result: QueryResultBody
}

#[derive(Deserialize, Debug)]
struct QueryResultBody {
    response: QueryResultResponse
}

#[derive(Deserialize, Debug)]
struct QueryResultResponse {
    code: i32,
    log: String,
    value: Option<String>
}

/*{
  "error": "",
  "result": {
    "response": {
      "log": "exists",
      "height": "0",
      "proof": "010114FED0DAD959F36091AD761C922ABA3CBF1D8349990101020103011406AA2262E2F448242DF2C2607C3CDC705313EE3B0001149D16177BC71E445476174622EA559715C293740C",
      "value": "61626364",
      "key": "61626364",
      "index": "-1",
      "code": "0"
    }
  },
  "id": "",
  "jsonrpc": "2.0"
}*/