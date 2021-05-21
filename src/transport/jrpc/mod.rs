use std::sync::Arc;

use anyhow::Result;
use models::*;
use serde::Serialize;
use ton_block::{Block, Deserializable, MsgAddressInt};

use crate::core::models::TransactionId;
use crate::external::{JrpcConnection, JrpcRequest};
use crate::transport::models::{RawContractState, RawTransaction};
use crate::utils::TrustMe;

use super::Transport;
use crate::transport::utils::ConfigCache;

mod models;

pub struct JrpcTransport {
    connection: Arc<dyn JrpcConnection>,
    config_cache: ConfigCache,
}

impl JrpcTransport {
    pub fn new(connection: Arc<dyn JrpcConnection>) -> Self {
        Self {
            connection,
            config_cache: ConfigCache::new(),
        }
    }
}

fn request_data<T>(method: &str, params: Option<T>) -> JrpcRequest
where
    T: Serialize,
{
    JrpcRequest {
        method,
        params: serde_json::to_value(params).trust_me(),
    }
}

#[async_trait::async_trait]
impl Transport for JrpcTransport {
    fn max_transactions_per_fetch(&self) -> u8 {
        16
    }

    async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        let param = SendMessage { message };
        let data = request_data("sendMessage", Some(param));
        self.connection.post(data).await.map(|_| ())
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        let message = GetContractState {
            address: address.clone(),
        };
        let data = self
            .connection
            .post(request_data("getContractState", Some(message)))
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
        let data = self
            .connection
            .post(request_data("getTransactions", Some(obj)))
            .await?;
        let parsed: RawTransactionsList = tiny_jsonrpc::parse_response(&data)?;
        let transactions =
            ton_types::deserialize_cells_tree(&mut std::io::Cursor::new(&parsed.transactions))
                .map_err(|_| anyhow::anyhow!("Invalid transaction list"))?;

        let mut result = Vec::with_capacity(transactions.len());
        for item in transactions.into_iter() {
            let hash = item.repr_hash();
            result.push(RawTransaction {
                hash,
                data: ton_block::Transaction::construct_from_cell(item)
                    .map_err(|_| anyhow::anyhow!("Invalid transaction"))?,
            });
        }
        Ok(result)
    }

    async fn get_latest_key_block(&self) -> Result<Block> {
        self.connection
            .post(request_data::<String>("getLatestKeyBlock", None))
            .await
            .map(|data| tiny_jsonrpc::parse_response(&data))?
            .map(|block: RawBlock| block.block)
    }

    async fn get_blockchain_config(&self) -> Result<ton_executor::BlockchainConfig> {
        self.config_cache.get_blockchain_config(self).await
    }
}

#[cfg(test)]
#[cfg(feature = "integration_test")]
mod test {
    use super::Transport;
    use crate::core::models::TransactionId;
    use crate::external::{JrpcConnection, JrpcRequest};
    use anyhow::Result;
    use std::str::FromStr;
    use std::sync::Arc;
    use ton_block::MsgAddressInt;
    use ton_types::UInt256;

    #[async_trait::async_trait]
    impl JrpcConnection for reqwest::Client {
        async fn post<'a>(&self, req: JrpcRequest<'a>) -> Result<String> {
            let url = "http://127.0.0.1:9000/rpc".to_string();
            let data = serde_json::json!({
                "jsonrpc": "2.0",
                "method": req.method,
                "params": req.params,
                "id": 1
            });
            println!("{}", serde_json::to_string(&data).unwrap());
            let res = self.post(url).json(&data).send().await?.text().await?;
            // println!("{}", res);
            Ok(res)
        }
    }

    #[tokio::test]
    async fn test_key_block() {
        let client = Arc::new(reqwest::Client::new());
        let transport = super::JrpcTransport::new(client);
        let id = transport.get_latest_key_block().await.unwrap().global_id;
        println!("{}", id);
    }

    #[tokio::test]
    async fn test_get_state() {
        let client = Arc::new(reqwest::Client::new());
        let transport = super::JrpcTransport::new(client);
        let id = transport
            .get_contract_state(
                &MsgAddressInt::from_str(
                    "-1:5555555555555555555555555555555555555555555555555555555555555555",
                )
                .unwrap(),
            )
            .await
            .unwrap()
            .brief()
            .balance;
        println!("{}", id);
    }

    #[tokio::test]
    async fn test_get_tranactions() {
        let client = Arc::new(reqwest::Client::new());
        let transport = super::JrpcTransport::new(client);
        let id = transport
            .get_transactions(
                MsgAddressInt::from_str(
                    "-1:5555555555555555555555555555555555555555555555555555555555555555",
                )
                .unwrap(),
                TransactionId {
                    hash: UInt256::from_str(
                        "0100be1d1d48389cace7370792caea3273bd071d000d1263cf6cda27cbb87a0e",
                    )
                    .unwrap(),
                    lt: 14313437000003,
                },
                10,
            )
            .await
            .unwrap()
            .len();
        println!("{}", id);
    }

    #[tokio::test]
    async fn test_get_config() {
        let client = Arc::new(reqwest::Client::new());
        let transport = super::JrpcTransport::new(client);
        let id = transport
            .get_blockchain_config()
            .await
            .unwrap()
            .get_fwd_prices(true)
            .cell_price;

        println!("{}", id);
    }
}
