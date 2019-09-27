use std::collections::HashMap;
use log::LevelFilter;
use sha2::{Sha512, Digest};

use serde::{Deserialize};
use core_fpi::{G, rnd_scalar, KeyEncoder, HardKeyDecoder, Scalar, RistrettoPoint, CompressedRistretto};

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
    admin = "<public-key-base64>"       # Set the management key authorized for negotiations

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
    pub index: usize,
    pub secret: Scalar,
    pub pkey: RistrettoPoint,

    pub threshold: usize,
    pub port: usize,

    pub log: LevelFilter,
    pub admin: RistrettoPoint,
    
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
        let admin: CompressedRistretto = t_cfg.admin.decode();
        
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

        let pkey = pkey.decompress().expect("Unable to decompress pkey!");
        let index = peers.iter().position(|item| item.pkey == pkey).expect("Configuration error! Expecting to find the corresponding peer index!");
        
        let llog = match t_cfg.log.as_ref() {
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            _ => panic!("Log level not recognized!")
        };

        Self {
            name: t_cfg.name,
            index: index,
            secret: t_cfg.secret.decode(),
            pkey: pkey,
            
            threshold: t_cfg.threshold,
            port: t_cfg.port,

            log: llog,
            admin: admin.decompress().expect("Unable to decompress mng-key!"),

            peers_hash: hasher.result().to_vec(),
            peers: peers
        }
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
    admin: String,

    peers: HashMap<String, TomlPeer>
}

#[derive(Deserialize, Debug)]
struct TomlPeer {
    name: String,
    pkey: String
}