pub mod consents;
pub mod ids;
pub mod records;
pub mod keys;
pub mod messages;

pub trait ID {
    fn id(&self) -> &str;
}