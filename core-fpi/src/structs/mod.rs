pub mod authorizations;
pub mod disclosures;
pub mod ids;
pub mod records;
pub mod keys;
pub mod messages;

use std::time::Duration;
use crate::Result;
use crate::ids::Subject;

//-------------------------------------------------------------------------------------------------------
// Default field constraints (these are input bounds, not database bounds)
//-------------------------------------------------------------------------------------------------------
const MAX_PEERS: usize = 256;

const MAX_HASH_SIZE: usize = 256;
const MAX_SESSION_SIZE: usize = 256;
const MAX_KEY_ID_SIZE: usize = 32;

const MAX_SUBJECT_ID_SIZE: usize = 256;
const MAX_SUBJECT_KEY_SIZE: usize = 16;

const MAX_PROFILES: usize = 16;
const MAX_PROFILE_ID_SIZE: usize = 128;

const MAX_LOCATIONS: usize = 16;
const MAX_LOCATION_ID_SIZE: usize = 512;

const MAX_KEY_CHAIN: usize = 16;

const MAX_DATA_SIZE: usize = 1024 * 1024;


pub trait Constraints {
    fn sid(&self) -> &str;
    fn verify(&self, subject: &Subject, threshold: Duration) -> Result<()>;
}