use anyhow::Result;
use async_trait::async_trait;
#[cfg(feature = "adnl_transport")]
use ton_api::ton;

#[async_trait]
pub trait Storage: Sync + Send {
    /// Retrieve data from storage
    async fn get(&self, key: &str) -> Result<Option<String>>;

    /// Upsert data into storage and wait until operation complete
    async fn set(&self, key: &str, value: &str) -> Result<()>;

    /// Upsert data into storage without waiting operation result
    fn set_unchecked(&self, key: &str, value: &str);

    /// Remove data from storage and wait until operation complete
    async fn remove(&self, key: &str) -> Result<()>;

    /// Remove data without waiting operation result
    fn remove_unchecked(&self, key: &str);
}

#[cfg(feature = "adnl_transport")]
#[async_trait]
pub trait AdnlConnection: Send + Sync {
    async fn query(&self, request: ton::TLObject) -> Result<ton::TLObject>;
}

#[cfg(feature = "gql_transport")]
#[async_trait]
pub trait GqlConnection: Send + Sync {
    async fn post(&self, data: &str) -> Result<String>;
}

#[cfg(feature = "jrpc_transport")]
#[async_trait]
pub trait JrpcConnection: Send + Sync {
    async fn post(&self, data: &str) -> Result<String>;
}

#[async_trait]
pub trait LedgerConnection: Send + Sync {
    async fn get_public_key(
        &self,
        account_id: u16,
    ) -> Result<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>;

    async fn sign(
        &self,
        account: u16,
        message: &[u8],
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]>;
}

#[cfg(test)]
pub mod test_impl {
    use super::*;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    pub struct StorageMap(Mutex<HashMap<String, String>>);

    impl StorageMap {
        pub fn new() -> Self {
            StorageMap(Default::default())
        }
    }

    #[async_trait]
    impl Storage for StorageMap {
        async fn get(&self, key: &str) -> Result<Option<String>> {
            Ok(self.0.lock().get(key).map(|x| x.clone()))
        }

        async fn set(&self, key: &str, value: &str) -> Result<()> {
            let _ = self.0.lock().insert(key.to_string(), value.to_string());
            Ok(())
        }

        fn set_unchecked(&self, key: &str, value: &str) {
            let _ = self.0.lock().insert(key.to_string(), value.to_string());
        }

        async fn remove(&self, key: &str) -> Result<()> {
            let _ = self.0.lock().remove(key);
            Ok(())
        }

        fn remove_unchecked(&self, key: &str) {
            let _ = self.0.lock().remove(key);
        }
    }
}
