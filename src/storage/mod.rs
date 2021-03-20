pub use keystore::mnemonics::*;
pub use keystore::StoredKey;

pub mod keystore;

pub trait KvStorage {
    type Error;
    fn get(&self, key: &str) -> Result<String, Self::Error>;
    fn set(&self, key: &str, value: &str) -> Result<(), Self::Error>;
}
