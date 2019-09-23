#[forbid(unsafe_code)]

use std::io::{Error, ErrorKind};
use clap::{Arg, App, SubCommand};

mod storage;

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
        .subcommand(SubCommand::with_name("cmd")
            .about("Controls the request command type")
            .arg(Arg::with_name("create")
                .takes_value(false)
                .help("Request the creation of a Subject")))
            .arg(Arg::with_name("evolve")
                .takes_value(true)
                .help("Request evolution of the subject key"))
        .get_matches();
    
    let host = matches.value_of("host").unwrap().to_owned();
    let sid = matches.value_of("sid").unwrap().to_owned();

    let mut sm = storage::SubjectManager::new(&sid, |msg| {
        let msg_data = msg.encode().map_err(|_| Error::new(ErrorKind::Other, "Unable to encode message (base64)!"))?;
        let data = base64::encode(&msg_data);
        let url = format!("http://{}/broadcast_tx_commit?tx={:?}", host, data.replace(&[' ', '+'][..], ""));

        println!("GET {}", url);
        let resp = reqwest::get(url.as_str()).map_err(|_| Error::new(ErrorKind::Other, "Unable to sync with network!"))?;
        
        println!("{:#?}", resp);
        Ok(())
    });

    if let Some(matches) = matches.subcommand_matches("cmd") {
        if matches.is_present("create") {
            sm.create().unwrap();
        } if matches.is_present("evolve") {
            sm.evolve().unwrap();
        } else {
            let url = format!("http://{}/status", host);
            
            println!("GET {}", url);
            let resp = reqwest::get(url.as_str()).unwrap();
            println!("{:#?}", resp);
        };
    }
}