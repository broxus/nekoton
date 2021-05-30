use std::sync::Arc;

use anyhow::Result;
use models::*;
use serde::Serialize;
use ton_block::{Block, Deserializable, MsgAddressInt};

use super::models::{ExistingContract, RawContractState, RawTransaction};
use super::utils::*;
use super::{Transport, TransportInfo};
use crate::core::models::{GenTimings, LastTransactionId, ReliableBehavior, TransactionId};
use crate::external::JrpcConnection;
use crate::utils::*;

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

#[async_trait::async_trait]
impl Transport for JrpcTransport {
    fn info(&self) -> TransportInfo {
        TransportInfo {
            max_transactions_per_fetch: 16,
            reliable_behavior: ReliableBehavior::IntensivePolling,
        }
    }

    async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        self.connection
            .post(&make_request("sendMessage", SendMessage { message }))
            .await
            .map(|_| ())
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        let data = self
            .connection
            .post(&make_request(
                "getContractState",
                GetContractState { address },
            ))
            .await?;
        let response = tiny_jsonrpc::parse_response::<GetContractStateResponse>(&data)?;
        Ok(match response {
            GetContractStateResponse::NotExists => RawContractState::NotExists,
            GetContractStateResponse::Exists(data) => RawContractState::Exists(ExistingContract {
                account: data.account,
                timings: GenTimings::Known {
                    gen_lt: data.timings.gen_lt,
                    gen_utime: data.timings.gen_utime,
                },
                last_transaction_id: LastTransactionId::Exact(data.last_transaction_id),
            }),
        })
    }

    async fn get_transactions(
        &self,
        address: MsgAddressInt,
        from: TransactionId,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        let response = self
            .connection
            .post(&make_request(
                "getTransactions",
                GetTransactions {
                    address: &address,
                    transaction_id: (from.lt != u64::MAX).then(|| from),
                    count,
                },
            ))
            .await?;
        let response: GetTransactionsResponse = tiny_jsonrpc::parse_response(&response)?;

        let transactions =
            ton_types::deserialize_cells_tree(&mut std::io::Cursor::new(&response.transactions))
                .map_err(|_| anyhow::anyhow!("Invalid transaction list"))?;

        let mut result = Vec::with_capacity(transactions.len());
        for item in transactions.into_iter().rev() {
            result.push(RawTransaction {
                hash: item.repr_hash(),
                data: ton_block::Transaction::construct_from_cell(item)
                    .map_err(|_| anyhow::anyhow!("Invalid transaction"))?,
            });
        }

        Ok(result)
    }

    async fn get_latest_key_block(&self) -> Result<Block> {
        self.connection
            .post(&make_request("getLatestKeyBlock", ()))
            .await
            .map(|data| tiny_jsonrpc::parse_response(&data))?
            .map(|block: GetBlockResponse| block.block)
    }

    async fn get_blockchain_config(&self) -> Result<ton_executor::BlockchainConfig> {
        self.config_cache.get_blockchain_config(self).await
    }
}

fn make_request<T>(method: &str, params: T) -> String
where
    T: Serialize,
{
    serde_json::to_string(&JrpcRequest { method, params }).trust_me()
}

struct JrpcRequest<'a, T> {
    method: &'a str,
    params: T,
}

impl<'a, T> Serialize for JrpcRequest<'a, T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut ser = serializer.serialize_struct("JrpcRequest", 4)?;
        ser.serialize_field("jsonrpc", "2.0")?;
        ser.serialize_field("id", &1)?;
        ser.serialize_field("method", self.method)?;
        ser.serialize_field("params", &self.params)?;
        ser.end()
    }
}

#[cfg(test)]
#[cfg(feature = "integration_test")]
mod test {
    use std::str::FromStr;
    use std::sync::Arc;

    use anyhow::Result;
    use ton_block::MsgAddressInt;
    use ton_types::UInt256;

    use super::Transport;
    use crate::core::models::TransactionId;
    use crate::external::JrpcConnection;

    #[async_trait::async_trait]
    impl JrpcConnection for reqwest::Client {
        async fn post(&self, data: &str) -> Result<String> {
            let url = "http://127.0.0.1:10000/rpc".to_string();

            let response = self
                .post(url)
                .body(data.to_string())
                .header("content-type", "application/json")
                .send()
                .await?;

            Ok(response.text().await?)
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
    async fn test_get_transactions() {
        let client = Arc::new(reqwest::Client::new());
        let transport = super::JrpcTransport::new(client);
        let transactions = transport
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
            .unwrap();

        assert_eq!(transactions.len(), 10);

        // Check if sorted in descending order
        assert!(transactions
            .windows(2)
            .all(|pair| pair[0].data.lt > pair[1].data.lt))
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
