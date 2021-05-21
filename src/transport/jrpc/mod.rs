use std::sync::Arc;

use anyhow::Result;
use serde::Serialize;
use ton_block::{Block, MsgAddressInt};
use ton_executor::BlockchainConfig;

use models::*;

use crate::core::models::TransactionId;
use crate::external::JrpcConnection;
use crate::transport::models::{RawContractState, RawTransaction};

use super::Transport;

mod models;

pub struct JrpcTransport {
    connection: Arc<dyn JrpcConnection>,
}

impl JrpcTransport {
    pub fn new(connection: Arc<dyn JrpcConnection>) -> Self {
        Self { connection }
    }
}

fn request_data(method: &str, params: Option<Vec<serde_json::Value>>) -> serde_json::Value {
    #[derive(Serialize)]
    struct JrpcRequest<'a> {
        pub method: &'a str,
        pub params: serde_json::Value,
    }

    let data = JrpcRequest {
        method,
        params: serde_json::json!(params),
    };
    serde_json::json!(data)
}

#[async_trait::async_trait]
impl Transport for JrpcTransport {
    fn max_transactions_per_fetch(&self) -> u8 {
        16
    }

    async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        let param = serde_json::to_value(SendMessage { message })?;
        let data = request_data("send_message", Some(vec![param]));
        self.connection.post(data).await.map(|_| ())
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        let message = GetContractState {
            address: address.clone(),
        };
        let data = self
            .connection
            .post(request_data(
                "get_contract_state",
                Some(vec![serde_json::json!(message)]),
            ))
            .await?;
        tiny_jsonrpc::parse_response(&data)
    }

    async fn get_transactions(
        &self,
        address: MsgAddressInt,
        from: TransactionId,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        let transaction_id = TransactionId {
            hash: from.hash,
            lt: from.lt,
        };
        let obj = GetTransactions {
            address,
            transaction_id,
            count,
        };
        let data: RawTransactionsList = self
            .connection
            .post(request_data(
                "send_message",
                Some(vec![serde_json::json!((obj))]),
            ))
            .await
            .map(|data| tiny_jsonrpc::parse_response(&data))??;
        // data.transactions
        todo!("howto map")
    }

    async fn get_latest_key_block(&self) -> Result<Block> {
        self.connection
            .post(request_data("get_latest_key_block", None))
            .await
            .map(|data| tiny_jsonrpc::parse_response(&data))?
            .map(|block: RawBlock| block.block)
    }

    async fn get_blockchain_config(&self) -> Result<BlockchainConfig> {
        todo!("Not impleneted on server side")
    }
}
