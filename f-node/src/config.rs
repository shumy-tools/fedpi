use std::collections::HashMap;

use serde::{Deserialize};
use core_fpi::{G, rnd_scalar, KeyEncoder, HardKeyDecoder, Scalar, RistrettoPoint, CompressedRistretto};

fn cfg_default() -> String {
    let secret = rnd_scalar();
    let pkey = (secret * G).compress();

    format!(r#"
    secret = {:?}     # Scalar
    pkey = {:?}       # CompressedRistretto  (not included in the peers)
    threshold = 0     # where #peers >= 3 * t

    # List of valid peers
    [peers]
    "#, secret.encode(), pkey.encode())
}

#[derive(Debug)]
pub struct Peer {
    pub name: String,
    pub pkey: RistrettoPoint
}

#[derive(Debug)]
pub struct Config {
    pub secret: Scalar,
    pub pkey: RistrettoPoint,

    pub threshold: usize,
    pub peers: Vec<Peer>
}

impl Config {
    pub fn new(path: &str) -> Self {
        let filename = format!("{}/config/app.config.toml", path);
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
        
        let mut peers = Vec::<Peer>::with_capacity(t_cfg.peers.len());
        for i in 0..t_cfg.peers.len() {
            let index = format!("{}", i);
            let peer = t_cfg.peers.get(&index).ok_or(format!("Expected peer at index {}!", i)).unwrap();

            let pkey: CompressedRistretto = peer.pkey.decode();
            let pkey = pkey.decompress().expect(&format!("Unable to decompress peer-key: {}", peer.name));
            let peer = Peer { name: peer.name.clone(), pkey: pkey };

            peers.push(peer);
        }

        Self {
            secret: t_cfg.secret.decode(),
            pkey: pkey.decompress().expect("Unable to decompress pkey!"),
            threshold: t_cfg.threshold,
            peers: peers
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
    peers: HashMap<String, TomlPeer>
}

#[derive(Deserialize, Debug)]
struct TomlPeer {
    name: String,
    pkey: String
}