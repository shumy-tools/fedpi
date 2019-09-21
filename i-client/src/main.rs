#[forbid(unsafe_code)]
use clap::{Arg, App, SubCommand};

mod store;

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

    let store = store::Store::new(&sid).unwrap();

    if let Some(matches) = matches.subcommand_matches("cmd") {
        let url = if matches.is_present("create") {
            let msg = store.create().unwrap().encode().unwrap();
            let data = base64::encode(&msg);
            format!("http://{}/broadcast_tx_commit?tx={:?}", host, data.trim())
        } else {
            format!("http://{}/status", host)
        };

        println!("GET {}", url);
        let resp = reqwest::get(url.as_str()).unwrap();
        println!("{:#?}", resp);
    }
}