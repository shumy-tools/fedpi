use std::collections::HashMap;
use log::LevelFilter;
use sha2::{Sha512, Digest};

use serde::{Deserialize};
use core_fpi::{G, rnd_scalar, Result, KeyEncoder, HardKeyDecoder, Scalar, RistrettoPoint, CompressedRistretto};

fn cfg_default() -> String {
    let secret = rnd_scalar();
    let pkey = (secret * G).compress();

    format!(r#"
    name = "<no-name>"                  # Set the name of the node here
    secret = {:?}                       # Scalar
    pkey = {:?}                         # CompressedRistretto  (not included in the peers)
    
    threshold = 0                       # Number of permitted failing nodes, where #peers >= 3 * t
    port = 26658                        # Set the service port for tendermint

    log = "info"                        # Set the log level
    mng_key = "<public-key-base64>"     # Set the management key authorized for negotiations

    # List of valid peers
    [peers]
    "#, secret.encode(), pkey.encode())
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub name: String,
    pub pkey: RistrettoPoint
}

#[derive(Debug, Clone)]
pub struct Config {
    pub name: String,
    pub secret: Scalar,
    pub pkey: RistrettoPoint,

    pub threshold: usize,
    pub port: usize,

    pub log: LevelFilter,
    pub mng_key: RistrettoPoint,
    
    pub peers_hash: Vec<u8>,
    pub peers: Vec<Peer>
}

impl Config {
    pub fn new(home: &str) -> Self {
        let filename = format!("{}/config/app.config.toml", home);
        
        let cfg = match std::fs::read_to_string(&filename) {
            Ok(content) => content,
            Err(e) => {
                let def_cfg = cfg_default();
                std::fs::write(&filename, &def_cfg).expect(&format!("Problems when creating the default config file: {}", e));
                def_cfg
            }
        };

        let t_cfg: TomlConfig = toml::from_str(&cfg).expect("Unable to decode toml configuration!");
        let pkey: CompressedRistretto = t_cfg.pkey.decode();
        let mng_key: CompressedRistretto = t_cfg.mng_key.decode();
        
        let mut peers = Vec::<Peer>::with_capacity(t_cfg.peers.len());
        let mut hasher = Sha512::new();
        for i in 0..t_cfg.peers.len() {
            let index = format!("{}", i);
            let peer = t_cfg.peers.get(&index).ok_or(format!("Expected peer at index {}!", i)).unwrap();

            let pkey: CompressedRistretto = peer.pkey.decode();
            hasher.input(pkey.as_bytes());

            let pkey = pkey.decompress().expect(&format!("Unable to decompress peer-key: {}", peer.name));
            let peer = Peer { name: peer.name.clone(), pkey: pkey };

            peers.push(peer);
        }
        
        let llog = match t_cfg.log.as_ref() {
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            _ => panic!("Log level not recognized!")
        };

        Self {
            name: t_cfg.name,
            secret: t_cfg.secret.decode(),
            pkey: pkey.decompress().expect("Unable to decompress pkey!"),
            
            threshold: t_cfg.threshold,
            port: t_cfg.port,

            log: llog,
            mng_key: mng_key.decompress().expect("Unable to decompress mng-key!"),

            peers_hash: hasher.result().to_vec(),
            peers: peers
        }
    }

    pub fn key_index(&self) -> Result<usize> {
        self.peers.iter().position(|item| item.pkey == self.pkey)
            .ok_or("Configuration error! Expecting to find the peer-key index!")
    }
}

//--------------------------------------------------------------------------------------------
// Structure of the configuration file (app.config.toml)
//--------------------------------------------------------------------------------------------
#[derive(Deserialize, Debug)]
struct TomlConfig {
    name: String,
    secret: String,
    pkey: String,

    threshold: usize,
    port: usize,

    log: String,
    mng_key: String,

    peers: HashMap<String, TomlPeer>
}

#[derive(Deserialize, Debug)]
struct TomlPeer {
    name: String,
    pkey: String
}