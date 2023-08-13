use anyhow::Result;
use serde::{Deserialize, Serialize};
use nekoton_utils::serde_optional_hex_array;

#[cfg(feature = "proto_transport")]
use nekoton_proto::rpc;

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
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
#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
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
#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
pub trait JrpcConnection: Send + Sync {
    async fn post(&self, req: JrpcRequest) -> Result<String>;
}

#[cfg(feature = "proto_transport")]
#[derive(Debug, Clone)]
pub struct ProtoRequest {
    pub data: rpc::Request,
    pub requires_db: bool,
}

#[cfg(feature = "proto_transport")]
#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
pub trait ProtoConnection: Send + Sync {
    async fn post(&self, req: ProtoRequest) -> Result<rpc::Response>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerSignatureContext {
    pub decimals: u8,
    pub asset: String,
    #[serde(default)]
    pub workchain_id: Option<i8>,
    #[serde(default, with = "serde_optional_hex_array")]
    pub address: Option<[u8; 32]>,
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
pub trait LedgerConnection: Send + Sync {
    async fn get_public_key(
        &self,
        account_id: u16,
    ) -> Result<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>;

    async fn sign(
        &self,
        account: u16,
        signature_id: Option<i32>,
        message: &[u8],
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]>;

    async fn sign_transaction(
        &self,
        account: u16,
        wallet: u16,
        signature_id: Option<i32>,
        message: &[u8],
        context: &LedgerSignatureContext,
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]>;
}
