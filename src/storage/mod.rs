pub use keystore::recovery::*;
pub use keystore::StoredKey;

pub mod keystore;

pub trait KvStorage {
    type Error;
    fn get(key: &str) -> Result<String, Self::Error>;
    fn set(key: &str, value: &str) -> Result<(), Self::Error>;
}
