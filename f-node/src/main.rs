#![forbid(unsafe_code)]

use std::io::Write;
use clap::{Arg, App};

use env_logger::fmt::Color;

use log::info;
use log::Level::{Info, Warn, Error};

mod db;
mod config;
mod handlers;
mod processor;
mod tendermint;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let matches = App::new("FedPI Node")
        .version(VERSION)
        .about("The official FedPI Node implementation.")
        .author("Micael Pedrosa <micaelpedrosa@ua.pt>")
        .arg(Arg::with_name("home")
            .help("Set the node-app config directory.")
            .required(false)
            .short("h")
            .long("home")
            .takes_value(true))
        .get_matches();
    
    let home = matches.value_of("home").unwrap_or(".");
    let home = if home.ends_with('/') { &home[..home.len()-1] } else { home };

    // read configuration from HOME/config/app.config.toml file
    let cfg = config::Config::new(&home);

    let addr = format!("127.0.0.1:{}", cfg.port).parse().unwrap();

    // config logger
    let cfg_clone = cfg.clone();
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
            
            writeln!(buf, "[{} - {} {}] {}", &cfg_clone.name, buf.timestamp(), style.value(record.level()), record.args())
        })
        .filter(None, cfg.log)
        .init();

    info!("Initializing FedPI Node (Tendermint) at port: {}", cfg.port);

    // init message processor (generic processor that doesn't depend on tendermint)
    let prc = processor::Processor::new(cfg);
    abci::run(addr, tendermint::NodeApp { height: 0, processor: prc });
}