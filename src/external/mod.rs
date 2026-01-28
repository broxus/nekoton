use anyhow::Result;
use nekoton_utils::serde_optional_hex_array;
use serde::{Deserialize, Serialize};

use super::crypto::SignatureDomain;

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
    pub data: Vec<u8>,
    pub requires_db: bool,
}

#[cfg(feature = "proto_transport")]
#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
pub trait ProtoConnection: Send + Sync {
    async fn post(&self, req: ProtoRequest) -> Result<Vec<u8>>;
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
        signature_domain: SignatureDomain,
        message: &[u8],
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]>;

    async fn sign_transaction(
        &self,
        account: u16,
        wallet: u16,
        signature_id: SignatureDomain,
        message: &[u8],
        context: &LedgerSignatureContext,
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]>;
}

#[cfg(feature = "jrpc_transport")]
pub enum JrpcResponse<T> {
    Success(T),
    Err(Box<serde_json::value::RawValue>),
}

#[cfg(feature = "jrpc_transport")]
impl<'de, T> Deserialize<'de> for JrpcResponse<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::marker::PhantomData;

        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Field {
            Result,
            Error,
            #[serde(other)]
            Other,
        }

        enum ResponseData<T> {
            Result(T),
            Error(Box<serde_json::value::RawValue>),
        }

        struct ResponseVisitor<T>(PhantomData<T>);

        impl<'de, T> serde::de::Visitor<'de> for ResponseVisitor<T>
        where
            T: Deserialize<'de>,
        {
            type Value = ResponseData<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON-RPC response object")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut result = None::<ResponseData<T>>;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Result if result.is_none() => {
                            result = Some(map.next_value().map(ResponseData::Result)?);
                        }
                        Field::Error if result.is_none() => {
                            result = Some(map.next_value().map(ResponseData::Error)?);
                        }
                        Field::Other => {
                            map.next_value::<&serde_json::value::RawValue>()?;
                        }
                        Field::Result => return Err(serde::de::Error::duplicate_field("result")),
                        Field::Error => return Err(serde::de::Error::duplicate_field("error")),
                    }
                }

                result.ok_or_else(|| serde::de::Error::missing_field("result or error"))
            }
        }

        Ok(match de.deserialize_map(ResponseVisitor(PhantomData))? {
            ResponseData::Result(result) => JrpcResponse::Success(result),
            ResponseData::Error(error) => JrpcResponse::Err(error),
        })
    }
}
