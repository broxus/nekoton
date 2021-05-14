use std::sync::Arc;

use adnl_rpc_models::GetTransactions;
use anyhow::Result;
use serde_json::Value;
use tiny_jsonrpc::params::Params;
use ton_block::{Block, Message, MsgAddressInt};
use ton_executor::BlockchainConfig;

use crate::core::models::TransactionId;
use crate::external::{AdnlConnection, JrpcAdnlConnection};
use crate::transport::models::{RawContractState, RawTransaction};

use super::Transport;

pub struct AndlRpc {
    connection: Arc<dyn JrpcAdnlConnection>,
}

impl AndlRpc {
    pub fn new(connection: Arc<dyn JrpcAdnlConnection>) -> Self {
        Self { connection }
    }
}

#[async_trait::async_trait]
impl Transport for AndlRpc {
    fn max_transactions_per_fetch(&self) -> u8 {
        16
    }

    async fn send_message(&self, message: &Message) -> Result<()> {
        use adnl_rpc_models::SendMessage;
        let message = SendMessage {
            message: message.clone(),
        };

        self.connection
            .send(
                "send_message",
                Params::Array(vec![serde_json::json!(message)]),
            )
            .await
            .map(|_| ())
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        use adnl_rpc_models::SendMessage;
        let message = SendMessage {
            message: message.clone(),
        };

        self.connection
            .send(
                "get_contract_state",
                Params::Array(vec![serde_json::json!(message)]),
            )
            .await
            .map()
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
