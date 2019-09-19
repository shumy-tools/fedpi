#[forbid(unsafe_code)]

use std::io::Write;
use clap::{Arg, App};

use env_logger::fmt::Color;

use log::Level::{Info, Warn, Error};
use log::{info, LevelFilter};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

mod tendermint;

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
        .get_matches();
    
    let name = matches.value_of("name").unwrap().to_owned();

    let str_port = matches.value_of("port");
    let port: usize = match str_port {
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

    // default to tendermint...
    info!("Initializing FedPI Node at port: {}", port);
    abci::run(addr, tendermint::NodeApp);
}