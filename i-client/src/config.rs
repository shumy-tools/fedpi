use std::collections::HashMap;
use log::LevelFilter;
use sha2::{Sha512, Digest};
use clear_on_drop::clear::Clear;

use serde::{Deserialize};
use core_fpi::{G, rnd_scalar, KeyEncoder, HardKeyDecoder, Scalar, RistrettoPoint, CompressedRistretto};

fn cfg_default() -> String {
    let secret = rnd_scalar();
    let pkey = (secret * G).compress();

    format!(r#"
    secret = {:?}       # Scalar
    pkey = {:?}         # CompressedRistretto  (not included in the peers)
    
    threshold = 0       # Number of permitted failing nodes, where #peers >= 3 * t
    log = "info"        # Set the log level

    # List of valid peers
    [peers]
    "#, secret.encode(), pkey.encode())
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub host: String,
    pub pkey: RistrettoPoint
}

#[derive(Debug, Clone)]
pub struct Config {
    pub secret: Scalar,
    pub pkey: RistrettoPoint,

    pub threshold: usize,

    pub log: LevelFilter,

    pub peers_hash: Vec<u8>,
    pub peers: Vec<Peer>
}

impl Drop for Config {
    fn drop(&mut self) {
        self.secret.clear();
    }
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
        let pkey: CompressedRistretto = t_cfg.pkey.decode();
        
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

        let llog = match t_cfg.log.as_ref() {
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            _ => panic!("Log level not recognized!")
        };

        Self {
            secret: t_cfg.secret.decode(),
            pkey: pkey.decompress().expect("Unable to decompress pkey!"),
            
            threshold: t_cfg.threshold,

            log: llog,

            peers_hash: hasher.result().to_vec(),
            peers
        }
    }
}

//--------------------------------------------------------------------------------------------
// Structure of the configuration file (app.config.toml)
//--------------------------------------------------------------------------------------------
#[derive(Deserialize, Debug)]
struct TomlConfig {
    secret: String,
    pkey: String,

    threshold: usize,
    log: String,

    peers: HashMap<String, TomlPeer>
}

#[derive(Deserialize, Debug)]
struct TomlPeer {
    host: String,
    pkey: String
}