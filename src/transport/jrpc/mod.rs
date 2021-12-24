use std::sync::Arc;

use anyhow::Result;
use serde::Serialize;
use ton_block::{Block, Deserializable, MsgAddressInt};

use nekoton_abi::TransactionId;
use nekoton_utils::*;

use crate::core::models::ReliableBehavior;
use crate::external::RestConnection;

use super::models::{RawContractState, RawTransaction};
use super::utils::*;
use super::{Transport, TransportInfo};

use self::models::*;

mod models;

pub struct JrpcConnection(Arc<dyn RestConnection>);

impl JrpcConnection {
    pub fn new(transport: Arc<dyn RestConnection>) -> Self {
        Self(transport)
    }

    pub fn transport_info() -> TransportInfo {
        TransportInfo {
            max_transactions_per_fetch: 50,
            reliable_behavior: ReliableBehavior::IntensivePolling,
            has_key_blocks: true,
        }
    }

    pub fn connection(&self) -> &Arc<dyn RestConnection> {
        &self.0
    }
}

pub struct JrpcTransport {
    connection: JrpcConnection,
    config_cache: ConfigCache,
}

impl JrpcTransport {
    pub fn new(connection: JrpcConnection) -> Self {
        Self {
            connection,
            config_cache: ConfigCache::new(false),
        }
    }
}

#[async_trait::async_trait]
impl Transport for JrpcTransport {
    fn info(&self) -> TransportInfo {
        JrpcConnection::transport_info()
    }

    async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        let node = self.connection.connection();
        node.post(&make_jrpc_request("sendMessage", &SendMessage { message }))
            .await
            .map(|_| ())
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        let node = self.connection.connection();
        let data = node
            .post(&make_jrpc_request(
                "getContractState",
                &GetContractState { address },
            ))
            .await?;
        let response = tiny_jsonrpc::parse_response::<RawContractState>(&data)?;
        Ok(response)
    }

    async fn get_transactions(
        &self,
        address: MsgAddressInt,
        from: TransactionId,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        let response = self
            .connection
            .connection()
            .post(&make_jrpc_request(
                "getTransactionsList",
                &ExplorerGetTransactions {
                    limit: count as u64,
                    last_transaction_lt: (from.lt != u64::MAX).then(|| from.lt),
                    account: &address,
                },
            ))
            .await?;
        let data: Vec<String> = tiny_jsonrpc::parse_response(&response)?;
        Ok(decode_raw_transactions_response(&data)?)
    }

    async fn get_latest_key_block(&self) -> Result<Block> {
        let node = self.connection.connection();
        node.post(&make_jrpc_request("getLatestKeyBlock", &()))
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

fn decode_raw_transactions_response(response: &[String]) -> Result<Vec<RawTransaction>> {
    response
        .iter()
        .map(|x| {
            let bytes = base64::decode(x)?;
            let cell = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(bytes))?;
            let hash = cell.repr_hash();
            let data = ton_block::Transaction::construct_from(&mut cell.into())?;

            Ok(RawTransaction { hash, data })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use super::{JrpcConnection, JrpcTransport};

    const EMPTY_CELL_HASH: [u8; 32] = [
        0x96, 0xa2, 0x96, 0xd2, 0x24, 0xf2, 0x85, 0xc6, 0x7b, 0xee, 0x93, 0xc3, 0x0f, 0x8a, 0x30,
        0x91, 0x57, 0xf0, 0xda, 0xa3, 0x5d, 0xc5, 0xb8, 0x7e, 0x41, 0x0b, 0x78, 0x63, 0x0a, 0x09,
        0xcf, 0xc7,
    ];

    #[test]
    fn test_jrpc_empty_transactions_list() {
        let response = base64::decode("te6ccgEBAQEAAgAAAA==").unwrap();

        let transactions =
            ton_types::deserialize_cells_tree(&mut std::io::Cursor::new(response)).unwrap();

        assert_eq!(transactions.len(), 1);
        assert_eq!(
            transactions.first().unwrap().repr_hash().as_slice(),
            &EMPTY_CELL_HASH
        );
    }

    #[async_trait::async_trait]
    impl RestConnection for reqwest::Client {
        async fn post(&self, data: &str) -> Result<String> {
            println!("{}", data);
            let text = self
                .post("https://extension-api.broxus.com/rpc")
                .body(data.to_string())
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
    async fn test_connection() {
        let connection = JrpcConnection::new(Arc::new(reqwest::Client::new()));
        let transport = JrpcTransport::new(connection);
        let address = ton_block::MsgAddressInt::from_str(
            "-1:3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap();
        transport.get_contract_state(&address).await.unwrap();
        transport
            .get_transactions(
                address,
                TransactionId {
                    lt: 21968513000000,
                    hash: ton_types::UInt256::from_slice(
                        &hex::decode(
                            "034009ed3d1d7ee2512e86d4e81fe9780d96503f539ae9a269ff9e8cfef21392",
                        )
                        .unwrap(),
                    ),
                },
                10,
            )
            .await
            .unwrap();
        transport.get_latest_key_block().await.unwrap();
    }
}
