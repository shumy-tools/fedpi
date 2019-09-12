#[forbid(unsafe_code)]

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand_os::OsRng;

mod macros;
mod shares;
mod signatures;
mod ssids;

// -- Exported --
pub use crate::shares::*;
pub use crate::signatures::*;
pub use crate::ssids::*;

pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

pub fn rnd_scalar() -> Scalar {
    let mut csprng: OsRng = OsRng::new().unwrap();
    Scalar::random(&mut csprng)
}