use anyhow::Result;
use async_trait::async_trait;
use nekoton_utils::*;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

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

#[cfg(feature = "gql_transport")]
#[async_trait]
pub trait GqlConnection: Send + Sync {
    fn is_local(&self) -> bool;

    async fn post(&self, data: &str) -> Result<String>;
}

#[cfg(feature = "jrpc_transport")]
#[async_trait]
pub trait JrpcConnection: Send + Sync {
    async fn post(&self, data: &str) -> Result<String>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerSignatureContext {
    pub decimals: u8,
    pub asset: String,
    #[serde(with = "serde_string")]
    pub amount: BigUint,
    #[serde(with = "serde_address")]
    pub address: ton_block::MsgAddressInt,
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
        context: &Option<LedgerSignatureContext>,
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]>;
}
