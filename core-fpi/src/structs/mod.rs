pub mod authorizations;
pub mod disclosures;
pub mod ids;
pub mod records;
pub mod keys;
pub mod messages;

use std::time::Duration;
use crate::Result;
use crate::ids::Subject;

pub trait Authenticated {
    fn sid(&self) -> &str;
    fn verify(&self, subject: &Subject, threshold: Duration) -> Result<()>;
}