#[forbid(unsafe_code)]
use clap::{Arg, App, SubCommand};

use core_fpi::{G, rnd_scalar, Scalar, CompressedRistretto};
use core_fpi::ids::*;

use core_fpi::messages::Message;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn create() -> Message {
    let sig_s = rnd_scalar();
    let sig_key = (sig_s * G).compress();

    let sid = "s-id:shumy";
    let skey1 = SubjectKey::new(sid, 0, sig_key, &sig_s, &sig_key);

    let mut sub = Subject::new(sid);
    sub.push_key(skey1);

    Message::SyncSubject(sub)
}

fn evolve(index: usize, sig_s: &Scalar, sig_key: &CompressedRistretto) -> Message {
    let new_key = (rnd_scalar() * G).compress();

    let sid = "s-id:shumy";
    let skey1 = SubjectKey::new(sid, index, new_key, &sig_s, &sig_key);

    let mut sub = Subject::new(sid);
    sub.push_key(skey1);

    Message::SyncSubject(sub)
}

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
        .subcommand(SubCommand::with_name("cmd")
            .about("Controls the request command type")
            .arg(Arg::with_name("create")
                .takes_value(false)
                .help("Request the creation of a Subject")))
            .arg(Arg::with_name("evolve")
                .takes_value(true)
                .help("Request evolution of the subject key"))
        .get_matches();
    
    let str_host = matches.value_of("host").unwrap().to_owned();

    if let Some(matches) = matches.subcommand_matches("cmd") {
        let url = if matches.is_present("create") {
            let msg = create().encode().unwrap();
            let data = base64::encode(&msg);
            format!("http://{}/broadcast_tx_commit?tx={:?}", str_host, data.trim())
        } else /*if matches.is_present("evolve") {
            let str_evolve = matches.value_of("evolve").unwrap().to_owned();
            let index = str_evolve.trim().parse::<usize>().unwrap();
            
            let msg = evolve(index).encode().unwrap();
            let data = base64::encode(&msg);
            format!("http://{}/broadcast_tx_commit?tx={:?}", str_host, data.trim())
        } else*/ {
            format!("http://{}/status", str_host)
        };

        println!("GET {}", url);
        let resp = reqwest::get(url.as_str()).unwrap();
        println!("{:#?}", resp);
    }
}