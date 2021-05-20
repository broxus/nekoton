use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;
use ton_block::{Deserializable, MsgAddressInt, Serializable};
use ton_executor::BlockchainConfig;

use crate::core::models::TransactionId;
use crate::external::{AdnlConnection, JrpcConnection};
use crate::transport::models::{RawContractState, RawTransaction};
use crate::utils::*;

use super::Transport;

pub struct JrpcTransport {
    connection: Arc<dyn JrpcConnection>,
}

impl JrpcTransport {
    pub fn new(connection: Arc<dyn JrpcConnection>) -> Self {
        Self { connection }
    }
}

struct JrpcRequest<'a> {
    pub method: &'a str,
    pub params: &'a dyn serde::Serialize,
}

#[async_trait::async_trait]
impl Transport for JrpcTransport {
    fn max_transactions_per_fetch(&self) -> u8 {
        16
    }

    async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        let param = serde_json::to_value(SendMessage { message })?;

        self.connection
            .send("send_message", Params::Array(vec![param]))
            .await
            .map(|_| ())
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        let message = SendMessage {
            message: message.clone(),
        };

        self.connection
            .send(
                "get_contract_state",
                Params::Array(vec![serde_json::json!(message)]),
            )
            .await;
    }

    async fn get_transactions(
        &self,
        address: MsgAddressInt,
        from: TransactionId,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        let transaction_id = adnl_rpc_models::TransactionId {
            hash: from.hash,
            lt: from.lt,
        };
        let obj = serde_json::json!(GetTransactions {
            address,
            transaction_id,
            count,
        });

        self.connection
            .send("send_message", Params::Array(vec![obj]))
            .await
            .map(|data| base64::decode(data))?
            .map()
    }

    async fn get_latest_key_block(&self) -> Result<Block> {
        self.connection
            .send("get_latest_key_block", Params::None)
            .await
            .map()
    }

    async fn get_blockchain_config(&self) -> Result<BlockchainConfig> {
        self.connection
            .send("get_blockchain_config", Params::None)
            .await
            .map()
    }
}

#[derive(Serialize)]
struct GetContractState {
    #[serde(with = "serde_address")]
    address: ton_block::MsgAddressInt,
}

#[derive(Serialize)]
struct SendMessage<'a> {
    #[serde(with = "serde_message")]
    message: &'a ton_block::Message,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GetTransactions {
    #[serde(with = "serde_address")]
    address: ton_block::MsgAddressInt,
    transaction_id: TransactionId,
    count: u8,
}

pub fn serialize_ton_block<S, T>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: Serializable,
{
    use serde::ser::Error;

    serde_cell::serialize(&data.serialize().map_err(S::Error::custom)?, serializer)
}
