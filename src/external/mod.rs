use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use nekoton_utils::serde_hex_array;

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
#[derive(Debug, Clone)]
pub struct GqlRequest {
    pub data: String,
    pub long_query: bool,
}

#[cfg(feature = "gql_transport")]
#[async_trait]
pub trait GqlConnection: Send + Sync {
    fn is_local(&self) -> bool;

    async fn post(&self, req: GqlRequest) -> Result<String>;
}

#[cfg(feature = "jrpc_transport")]
#[derive(Debug, Clone)]
pub struct JrpcRequest {
    pub data: String,
    pub requires_db: bool,
}

#[cfg(feature = "jrpc_transport")]
#[async_trait]
pub trait JrpcConnection: Send + Sync {
    async fn post(&self, req: JrpcRequest) -> Result<String>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum LedgerSignatureContext {
    Transfer(LedgerTransferContext),
    Confirm(LedgerConfirmationContext),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerTransferContext {
    pub decimals: u8,
    pub asset: String,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct LedgerConfirmationContext {
    #[serde(with = "serde_hex_array")]
    pub address: [u8; 32],
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

    async fn sign_transaction(
        &self,
        account: u16,
        wallet: u16,
        message: &[u8],
        context: &LedgerTransferContext,
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]>;

    async fn sign_confirmation(
        &self,
        account: u16,
        wallet: u16,
        message: &[u8],
        context: &LedgerConfirmationContext,
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]>;
}
