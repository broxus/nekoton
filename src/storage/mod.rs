use anyhow::Error;
pub use keystore::mnemonics::*;
pub use keystore::StoredKey;
pub mod keystore;

pub trait KvStorage {
    fn get(&self, key: &str) -> Result<String, Error>;
    fn set(&self, key: &str, value: &str) -> Result<(), Error>;
}
