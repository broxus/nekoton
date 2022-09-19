use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use ton_block::{Block, Deserializable, MsgAddressInt};

use nekoton_utils::*;

use crate::core::models::ReliableBehavior;
use crate::external::{self, JrpcConnection};

use super::models::{RawContractState, RawTransaction};
use super::utils::*;
use super::{Transport, TransportInfo};

use self::models::*;

mod models;

pub struct JrpcTransport {
    connection: Arc<dyn JrpcConnection>,
    config_cache: ConfigCache,
}

impl JrpcTransport {
    pub fn new(connection: Arc<dyn JrpcConnection>) -> Self {
        Self {
            connection,
            config_cache: ConfigCache::new(false),
        }
    }
}

#[async_trait::async_trait]
impl Transport for JrpcTransport {
    fn info(&self) -> TransportInfo {
        TransportInfo {
            max_transactions_per_fetch: 50,
            reliable_behavior: ReliableBehavior::IntensivePolling,
            has_key_blocks: true,
        }
    }

    async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        let req = external::JrpcRequest {
            data: make_jrpc_request("sendMessage", &SendMessage { message }),
            requires_db: false,
        };
        self.connection.post(req).await.map(|_| ())
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        let req = external::JrpcRequest {
            data: make_jrpc_request("getContractState", &GetContractState { address }),
            requires_db: false,
        };
        let data = self.connection.post(req).await?;
        let response = tiny_jsonrpc::parse_response::<RawContractState>(&data)?;
        Ok(response)
    }

    async fn get_accounts_by_code_hash(
        &self,
        code_hash: &ton_types::UInt256,
        limit: u8,
        continuation: &Option<MsgAddressInt>,
    ) -> Result<Vec<MsgAddressInt>> {
        let req = external::JrpcRequest {
            data: make_jrpc_request(
                "getAccountsByCodeHash",
                &GetAccountsByCodeHash {
                    limit: limit as u32,
                    continuation,
                    code_hash,
                },
            ),
            requires_db: true,
        };
        let data = self.connection.post(req).await?;

        #[derive(Deserialize)]
        struct AddressWrapper(#[serde(with = "serde_address")] MsgAddressInt);

        Ok(tiny_jsonrpc::parse_response::<Vec<AddressWrapper>>(&data)?
            .into_iter()
            .map(|AddressWrapper(address)| address)
            .collect())
    }

    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from_lt: u64,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        let req = external::JrpcRequest {
            data: make_jrpc_request(
                "getTransactionsList",
                &GetTransactions {
                    limit: count as u64,
                    last_transaction_lt: (from_lt != u64::MAX).then(|| from_lt),
                    account: address,
                },
            ),
            requires_db: true,
        };
        let response = self.connection.post(req).await?;
        let data: Vec<String> = tiny_jsonrpc::parse_response(&response)?;
        data.iter().map(|boc| decode_raw_transaction(boc)).collect()
    }

    async fn get_transaction(&self, id: &ton_types::UInt256) -> Result<Option<RawTransaction>> {
        let req = external::JrpcRequest {
            data: make_jrpc_request("getTransaction", &GetTransaction { id }),
            requires_db: true,
        };
        let response = self.connection.post(req).await?;
        let data: Option<String> = tiny_jsonrpc::parse_response(&response)?;
        data.map(|boc| decode_raw_transaction(&boc)).transpose()
    }

    async fn get_dst_transaction(
        &self,
        message_hash: &ton_types::UInt256,
    ) -> Result<Option<RawTransaction>> {
        let req = external::JrpcRequest {
            data: make_jrpc_request("getDstTransaction", &GetDstTransaction { message_hash }),
            requires_db: true,
        };
        let response = self.connection.post(req).await?;
        let data: Option<String> = tiny_jsonrpc::parse_response(&response)?;
        data.map(|boc| decode_raw_transaction(&boc)).transpose()
    }

    async fn get_latest_key_block(&self) -> Result<Block> {
        let req = external::JrpcRequest {
            data: make_jrpc_request("getLatestKeyBlock", &()),
            requires_db: true,
        };
        self.connection
            .post(req)
            .await
            .map(|data| tiny_jsonrpc::parse_response(&data))?
            .map(|block: GetBlockResponse| block.block)
    }

    async fn get_blockchain_config(
        &self,
        clock: &dyn Clock,
    ) -> Result<ton_executor::BlockchainConfig> {
        self.config_cache.get_blockchain_config(self, clock).await
    }
}

pub fn make_jrpc_request<S>(method: &str, params: &S) -> String
where
    S: Serialize,
{
    serde_json::to_string(&JrpcRequest { method, params }).trust_me()
}

pub struct JrpcRequest<'a, T> {
    method: &'a str,
    params: &'a T,
}

impl<'a, T> serde::Serialize for JrpcRequest<'a, T>
where
    T: serde::Serialize,
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
        ser.serialize_field("params", self.params)?;
        ser.end()
    }
}

fn decode_raw_transaction(boc: &str) -> Result<RawTransaction> {
    let bytes = base64::decode(boc)?;
    let cell = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())?;
    let hash = cell.repr_hash();
    let data = ton_block::Transaction::construct_from(&mut cell.into())?;
    Ok(RawTransaction { hash, data })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use futures_util::StreamExt;

    use super::*;

    #[async_trait::async_trait]
    impl JrpcConnection for reqwest::Client {
        async fn post(&self, req: external::JrpcRequest) -> Result<String> {
            println!("{req:?}");
            let text = self
                .post("https://jrpc.everwallet.net/rpc")
                .body(req.data)
                .header("Content-Type", "application/json")
                .send()
                .await?
                .text()
                .await?;
            // println!("{}", text);
            Ok(text)
        }
    }

    #[tokio::test]
    async fn test_transactions_stream() -> Result<()> {
        let transport = JrpcTransport::new(Arc::new(reqwest::Client::new()));

        let mut from_lt = 30526271000007;
        let test_address =
            "0:cd809fb1cde24b6d3cd4a3dd9102e10c0f73ddfa21c7118f233dc7309bbb0b73".parse()?;

        let mut transactions = crate::core::utils::request_transactions(
            &transport,
            &test_address,
            from_lt,
            None,
            2,
            None,
        );

        while let Some(transactions) = transactions.next().await {
            for transaction in transactions?.into_iter() {
                assert_eq!(transaction.data.lt, from_lt);
                from_lt = transaction.data.prev_trans_lt;
            }
        }

        assert_eq!(from_lt, 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_connection() -> Result<()> {
        let transport = JrpcTransport::new(Arc::new(reqwest::Client::new()));
        let address = MsgAddressInt::from_str(
            "-1:3333333333333333333333333333333333333333333333333333333333333333",
        )?;
        transport.get_contract_state(&address).await?;
        transport
            .get_transactions(&address, 21968513000000, 10)
            .await?;

        transport
            .get_transaction(&ton_types::UInt256::from_slice(
                &hex::decode("4a0a06bfbfaba4da8fcc7f5ad617fdee5344d954a1794e35618df2a4b349d15c")
                    .unwrap(),
            ))
            .await?
            .unwrap();

        let setcode_multisig_code_hash = ton_types::UInt256::from_str(
            "e2b60b6b602c10ced7ea8ede4bdf96342c97570a3798066f3fb50a4b2b27a208",
        )?;

        let mut continuation = None;
        loop {
            let contracts = transport
                .get_accounts_by_code_hash(&setcode_multisig_code_hash, 50, &continuation)
                .await?;

            continuation = contracts.last().cloned();
            if continuation.is_none() {
                break;
            }
        }

        transport.get_latest_key_block().await?;

        Ok(())
    }
}
