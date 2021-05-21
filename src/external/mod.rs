use anyhow::Result;
use async_trait::async_trait;
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

#[async_trait]
pub trait AdnlConnection: Send + Sync {
    async fn query(&self, request: ton::TLObject) -> Result<ton::TLObject>;
}

#[async_trait]
pub trait GqlConnection: Send + Sync {
    async fn post(&self, data: &str) -> Result<String>;
}

#[async_trait]
pub trait JrpcConnection: Send + Sync {
    async fn post(&self, data: serde_json::Value) -> Result<String>;
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
