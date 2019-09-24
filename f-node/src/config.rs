use serde::{Deserialize};
use core_fpi::{G, rnd_scalar, KeyEncoder, HardKeyDecoder, Scalar, CompressedRistretto};

fn cfg_default() -> String {
    let secret = rnd_scalar();
    let pkey = (secret * G).compress();

    format!(r#"
    secret = {:?}     # Scalar
    pkey = {:?}       # CompressedRistretto point
    "#, secret.encode(), pkey.encode())
}

#[derive(Debug)]
pub struct Config {
    pub secret: Scalar,
    pub pkey: CompressedRistretto
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
        Self { secret: t_cfg.secret.decode(), pkey: t_cfg.pkey.decode() }
    }
}

//--------------------------------------------------------------------------------------------
// Structure of the configuration file (app.config.toml)
//--------------------------------------------------------------------------------------------
#[derive(Deserialize)]
struct TomlConfig {
    secret: String,
    pkey: String
}