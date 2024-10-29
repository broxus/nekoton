use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use everscale_types::models::*;
use everscale_types::prelude::*;
use nekoton_core::transport::{ContractState, Transport};
use parking_lot::Mutex;
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::endpoint::Connection;
use crate::models::Timings;
use crate::LiveCheckResult;

#[derive(Clone)]
pub struct JrpcClient {
    client: reqwest::Client,
    endpoint: Arc<String>,
    was_dead: Arc<AtomicBool>,
    stats: Arc<Mutex<Option<Timings>>>,
}

impl JrpcClient {
    pub async fn post<Q, R>(&self, data: &Q) -> anyhow::Result<R>
    where
        Q: Serialize,
        for<'de> R: Deserialize<'de>,
    {
        let response = self
            .client
            .post(self.endpoint.as_str())
            .json(data)
            .send()
            .await?;

        let res = response.text().await?;
        match serde_json::from_str(&res)? {
            JrpcResponse::Success(res) => Ok(res),
            JrpcResponse::Err(err) => anyhow::bail!(err),
        }
    }
}

#[async_trait::async_trait]
impl Connection for JrpcClient {
    fn new(endpoint: Url, client: reqwest::Client) -> Self {
        JrpcClient {
            client,
            endpoint: Arc::new(endpoint.to_string()),
            was_dead: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Default::default()),
        }
    }

    fn endpoint(&self) -> &str {
        self.endpoint.as_str()
    }

    fn get_stats(&self) -> Option<Timings> {
        self.stats.lock().clone()
    }

    fn set_stats(&self, stats: Option<Timings>) {
        *self.stats.lock() = stats;
    }

    fn update_was_dead(&self, is_dead: bool) {
        self.was_dead.store(is_dead, Ordering::Release);
    }

    async fn is_alive_inner(&self) -> LiveCheckResult {
        let request = JrpcRequest {
            method: "getTimings",
            params: &(),
        };

        match self.post::<_, Timings>(&request).await {
            Ok(timings) => LiveCheckResult::Live(timings),
            Err(_) => LiveCheckResult::Dead,
        }
    }
}

#[async_trait::async_trait]
impl Transport for JrpcClient {
    async fn broadcast_message(&self, message: &DynCell) -> anyhow::Result<()> {
        #[derive(Serialize)]
        struct Params<'a> {
            #[serde(with = "Boc")]
            message: &'a DynCell,
        }

        self.post(&JrpcRequest {
            method: "sendMessage",
            params: &Params { message },
        })
        .await
    }

    async fn get_contract_state(&self, address: &StdAddr) -> anyhow::Result<ContractState> {
        #[derive(Serialize)]
        struct Params<'a> {
            address: &'a StdAddr,
        }

        self.post(&JrpcRequest {
            method: "getContractState",
            params: &Params { address },
        })
        .await
    }
}

struct JrpcRequest<'a, T> {
    method: &'a str,
    params: &'a T,
}

impl<'a, T: Serialize> Serialize for JrpcRequest<'a, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut ser = serializer.serialize_struct("JrpcRequest", 4)?;
        ser.serialize_field("jsonrpc", "2.0")?;
        ser.serialize_field("id", &1)?;
        ser.serialize_field("method", self.method)?;
        ser.serialize_field("params", self.params)?;
        ser.end()
    }
}

enum JrpcResponse<T> {
    Success(T),
    Err(Box<serde_json::value::RawValue>),
}

impl<'de, T> Deserialize<'de> for JrpcResponse<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(de: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
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
