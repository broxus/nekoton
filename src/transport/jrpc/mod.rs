use std::sync::Arc;

use anyhow::Result;
use serde::Serialize;
use ton_block::{Block, Deserializable, MsgAddressInt};

use nekoton_abi::{GenTimings, LastTransactionId, TransactionId};
use nekoton_utils::*;

use super::models::{ExistingContract, RawContractState, RawTransaction};
use super::rest_models::*;
use super::utils::*;
use super::{Transport, TransportInfo};
use crate::core::models::ReliableBehavior;
use crate::external::RestConnection;

pub struct JrpcTransport {
    connection: Arc<dyn RestConnection>,
    config_cache: ConfigCache,
}

impl JrpcTransport {
    pub fn new(connection: Arc<dyn RestConnection>) -> Self {
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
            max_transactions_per_fetch: 16,
            reliable_behavior: ReliableBehavior::IntensivePolling,
            has_key_blocks: true,
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

        if transactions.len() == 1 {
            let is_empty_cell = matches!(
                transactions.first(),
                Some(cell) if cell.repr_hash().as_slice() == &EMPTY_CELL_HASH
            );

            if is_empty_cell {
                return Ok(Vec::new());
            }
        }

        let mut result = Vec::with_capacity(transactions.len());
        for item in transactions {
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

    async fn get_blockchain_config(
        &self,
        clock: &dyn Clock,
    ) -> Result<ton_executor::BlockchainConfig> {
        self.config_cache.get_blockchain_config(self, clock).await
    }
}

const EMPTY_CELL_HASH: [u8; 32] = [
    0x96, 0xa2, 0x96, 0xd2, 0x24, 0xf2, 0x85, 0xc6, 0x7b, 0xee, 0x93, 0xc3, 0x0f, 0x8a, 0x30, 0x91,
    0x57, 0xf0, 0xda, 0xa3, 0x5d, 0xc5, 0xb8, 0x7e, 0x41, 0x0b, 0x78, 0x63, 0x0a, 0x09, 0xcf, 0xc7,
];

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
mod tests {
    use super::*;

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
}
