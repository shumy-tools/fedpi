#[forbid(unsafe_code)]

use std::io::Write;
use clap::{Arg, App};

use env_logger::fmt::Color;

use log::Level::{Info, Warn, Error};
use log::{info, LevelFilter};

mod config;
mod processor;
mod tendermint;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    let matches = App::new("FedPI Node")
        .version(VERSION)
        .about("The official FedPI Node implementation.")
        .author("Micael Pedrosa <micaelpedrosa@ua.pt>")
        .arg(Arg::with_name("name")
            .help("Set the node name.")
            .required(true)
            .short("n")
            .long("name")
            .takes_value(true))
        .arg(Arg::with_name("port")
            .help("Set the port number, default to 26658")
            .required(false)
            .short("p")
            .long("port")
            .takes_value(true))
        .arg(Arg::with_name("home")
            .help("Set the node-app config directory.")
            .required(false)
            .short("h")
            .long("home")
            .takes_value(true))
        .get_matches();
    
    let name = matches.value_of("name").unwrap().to_owned();
    let home = matches.value_of("home").unwrap_or("./");
    
    let port: usize = match matches.value_of("port") {
        None => 26658,
        Some(str_port) => str_port.trim().parse::<usize>().unwrap()
    };

    let addr = format!("127.0.0.1:{}", port).parse().unwrap();

    // config logger
    env_logger::builder()
        .format(move |buf, record| {
            let mut style = buf.style();
            style.set_bold(true);

            match record.level() {
                Info => style.set_color(Color::Green),
                Warn => style.set_color(Color::Yellow),
                Error => style.set_color(Color::Red),
                _ => &style /* do nothing */
            };
            
            writeln!(buf, "[{} - {} {}] {}", &name, buf.timestamp(), style.value(record.level()), record.args())
        })
        .filter(None, LevelFilter::Info)
        .init();

    // read configuration from HOME/config/app.config.toml file
    let cfg = config::Config::new(&home);

    // init message processor (generic processor that doesn't depend on tendermint)
    let prc = processor::Processor::new(cfg);

    // default to tendermint (it may change in the future)
    info!("Initializing FedPI Node (Tendermint) at port: {}", port);
    abci::run(addr, tendermint::NodeApp { processor: prc });
}