#![forbid(unsafe_code)]

use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE};
use rand_os::OsRng;

mod crypto;
mod structs;

// -- Exported --
pub use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto, RistrettoBasepointTable};
pub use curve25519_dalek::scalar::Scalar;

pub use crate::crypto::*;
pub use crate::structs::*;

pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
pub const G_TABLE: RistrettoBasepointTable = RISTRETTO_BASEPOINT_TABLE;

pub type Result<T> = std::result::Result<T, String>;

/*impl From<&'static str> for std::io::Error {
    fn from(msg: &'static str) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, format!("{}", msg))
    }
}*/

pub fn rnd_scalar() -> Scalar {
    let mut csprng: OsRng = OsRng::new().unwrap();
    Scalar::random(&mut csprng)
}

pub fn uuid() -> String {
    let r = rnd_scalar();
    bs58::encode(r.as_bytes()).into_string()
}

pub trait KeyEncoder {
    fn encode(&self) -> String;
}

pub trait HardKeyDecoder<T> {
    fn decode(&self) -> T;
}


impl KeyEncoder for CompressedRistretto {
    fn encode(&self) -> String {
        bs58::encode(self.as_bytes()).into_string()
    }
}

impl KeyEncoder for RistrettoPoint {
    fn encode(&self) -> String {
        bs58::encode(self.compress().as_bytes()).into_string()
    }
}

impl KeyEncoder for Scalar {
    fn encode(&self) -> String {
        bs58::encode(self.as_bytes()).into_string()
    }
}

impl HardKeyDecoder<CompressedRistretto> for String {
    fn decode(&self) -> CompressedRistretto {
        let data = bs58::decode(self.as_str()).into_vec().expect("Unable to decode base58 input!");
        CompressedRistretto::from_slice(&data)
    }
}

impl HardKeyDecoder<RistrettoPoint> for String {
    fn decode(&self) -> RistrettoPoint {
        let data = bs58::decode(self.as_str()).into_vec().expect("Unable to decode base58 input!");
        let point = CompressedRistretto::from_slice(&data);
        point.decompress().expect("Unable to decompress RistrettoPoint!")
    }
}

impl HardKeyDecoder<Scalar> for String {
    fn decode(&self) -> Scalar {
        let data = bs58::decode(self.as_str()).into_vec().expect("Unable to decode base58 input!");
        let mut bytes: [u8; 32] = Default::default();
        bytes.copy_from_slice(&data[0..32]);

        Scalar::from_canonical_bytes(bytes).expect("Unable to decode Scalar!")
    }
}