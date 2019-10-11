use std::collections::HashMap;
use log::LevelFilter;
use sha2::{Sha512, Digest};

use serde::{Deserialize};
use core_fpi::{HardKeyDecoder, RistrettoPoint, CompressedRistretto};

fn cfg_default() -> String {
    format!(r#"
    log = "info"        # Set the log level

    threshold = 0       # Number of permitted failing nodes, where #peers >= 3 * t
    
    # List of valid peers
    [peers]
    "#)
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub host: String,
    pub pkey: RistrettoPoint
}

#[derive(Debug, Clone)]
pub struct Config {
    pub log: LevelFilter,

    pub threshold: usize,
    pub peers_hash: Vec<u8>,
    pub peers: Vec<Peer>
}

impl Config {
    pub fn new(home: &str, sid: &str) -> Self {
        let filename = format!("{}/{}.toml", home, sid);
        
        let cfg = match std::fs::read_to_string(&filename) {
            Ok(content) => content,
            Err(_) => {
                let def_cfg = cfg_default();
                std::fs::write(&filename, &def_cfg).unwrap_or_else(|e| panic!("Problems when creating the default config file: {}", e));
                def_cfg
            }
        };

        let t_cfg: TomlConfig = toml::from_str(&cfg).expect("Unable to decode toml configuration!");
        
        let mut peers = Vec::<Peer>::with_capacity(t_cfg.peers.len());
        let mut hasher = Sha512::new();
        for i in 0..t_cfg.peers.len() {
            let index = format!("{}", i);
            let peer = t_cfg.peers.get(&index).unwrap_or_else(|| panic!("Expected peer at index {}!", i));

            let pkey: CompressedRistretto = peer.pkey.decode();
            hasher.input(pkey.as_bytes());

            let pkey = pkey.decompress().unwrap_or_else(|| panic!("Unable to decompress peer-key: {}", peer.host));

            let host = if peer.host.ends_with('/') { &peer.host[..peer.host.len()-1] } else { &peer.host };
            let peer = Peer { host: host.into(), pkey };

            peers.push(peer);
        }

        let log = match t_cfg.log.as_ref() {
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            _ => panic!("Log level not recognized!")
        };

        Self { log, threshold: t_cfg.threshold, peers_hash: hasher.result().to_vec(), peers }
    }
}

//--------------------------------------------------------------------------------------------
// Structure of the configuration file (app.config.toml)
//--------------------------------------------------------------------------------------------
#[derive(Deserialize, Debug)]
struct TomlConfig {
    log: String,
    
    threshold: usize,
    peers: HashMap<String, TomlPeer>
}

#[derive(Deserialize, Debug)]
struct TomlPeer {
    host: String,
    pkey: String
}