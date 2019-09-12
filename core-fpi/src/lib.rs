#[forbid(unsafe_code)]

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

mod macros;

mod core;
mod shares;
mod signatures;
mod ssids;

// -- Exported --
pub use crate::core::*;
pub use crate::shares::*;
pub use crate::signatures::*;
pub use crate::ssids::*;

pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;