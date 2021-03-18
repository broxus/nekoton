pub mod keystore;
pub use keystore::mnemonics::*;
pub use keystore::StoredKey;

pub trait KvStorage {
    type Error;
    fn get(key: &str) -> Result<String, Self::Error>;
    fn set(key: &str, value: &str) -> Result<(), Self::Error>;
}
