#[forbid(unsafe_code)]

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

use rand_os::OsRng;

mod macros;
mod crypto;
mod structs;

// -- Exported --
pub use crate::crypto::*;
pub use crate::structs::*;

pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
pub const FIRST: &str = "F";

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