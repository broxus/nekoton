use std::sync::Arc;

use anyhow::Result;
use nekoton_proto::prost::bytes::Bytes;
use nekoton_proto::rpc;
use nekoton_proto::utils;
use nekoton_proto::utils::{addr_to_bytes, bytes_to_addr};
use ton_block::{Block, Deserializable, MsgAddressInt, Serializable};

use nekoton_utils::*;

use crate::core::models::{NetworkCapabilities, ReliableBehavior};
use crate::external::{self, ProtoConnection};
use crate::transport::models::ExistingContract;

use super::models::{RawContractState, RawTransaction};
use super::utils::*;
use super::{Transport, TransportInfo};

pub struct ProtoTransport {
    connection: Arc<dyn ProtoConnection>,
    config_cache: ConfigCache,
}

impl ProtoTransport {
    pub fn new(connection: Arc<dyn ProtoConnection>) -> Self {
        Self {
            connection,
            config_cache: ConfigCache::new(false),
        }
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
impl Transport for ProtoTransport {
    fn info(&self) -> TransportInfo {
        TransportInfo {
            max_transactions_per_fetch: 50,
            reliable_behavior: ReliableBehavior::IntensivePolling,
            has_key_blocks: true,
        }
    }

    async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        let data = rpc::Request {
            call: Some(rpc::request::Call::SendMessage(rpc::request::SendMessage {
                message: message.write_to_bytes()?.into(),
            })),
        };

        let req = external::ProtoRequest {
            data,
            requires_db: false,
        };
        self.connection.post(req).await.map(|_| ())
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        let address = utils::addr_to_bytes(address);

        let data = rpc::Request {
            call: Some(rpc::request::Call::GetContractState(
                rpc::request::GetContractState { address },
            )),
        };

        let req = external::ProtoRequest {
            data,
            requires_db: false,
        };

        let response = self.connection.post(req).await?;
        match response.result {
            Some(rpc::response::Result::GetContractState(state)) => match state.contract_state {
                Some(state) => {
                    let account = utils::deserialize_account_stuff(&state.account)?;

                    let timings = state
                        .gen_timings
                        .ok_or::<ProtoClientError>(ProtoClientError::InvalidResponse)?
                        .into();

                    let last_transaction_id = state
                        .last_transaction_id
                        .ok_or::<ProtoClientError>(ProtoClientError::InvalidResponse)?
                        .into();

                    Ok(RawContractState::Exists(ExistingContract {
                        account,
                        timings,
                        last_transaction_id,
                    }))
                }
                None => Ok(RawContractState::NotExists),
            },
            _ => Err(ProtoClientError::InvalidResponse.into()),
        }
    }

    async fn get_accounts_by_code_hash(
        &self,
        code_hash: &ton_types::UInt256,
        limit: u8,
        continuation: &Option<MsgAddressInt>,
    ) -> Result<Vec<MsgAddressInt>> {
        let data = rpc::Request {
            call: Some(rpc::request::Call::GetAccountsByCodeHash(
                rpc::request::GetAccountsByCodeHash {
                    code_hash: code_hash.into_vec().into(),
                    continuation: continuation.as_ref().map(addr_to_bytes),
                    limit: limit as u32,
                },
            )),
        };

        let req = external::ProtoRequest {
            data,
            requires_db: false,
        };

        let response = self.connection.post(req).await?;
        match response.result {
            Some(rpc::response::Result::GetAccounts(accounts)) => accounts
                .account
                .iter()
                .map(bytes_to_addr)
                .collect::<Result<_>>(),
            _ => Err(ProtoClientError::InvalidResponse.into()),
        }
    }

    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from_lt: u64,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        let account = utils::addr_to_bytes(address);
        let data = rpc::Request {
            call: Some(rpc::request::Call::GetTransactionsList(
                rpc::request::GetTransactionsList {
                    account,
                    last_transaction_lt: (from_lt != u64::MAX).then_some(from_lt),
                    limit: count as u32,
                },
            )),
        };

        let req = external::ProtoRequest {
            data,
            requires_db: true,
        };

        let response = self.connection.post(req).await?;
        match response.result {
            Some(rpc::response::Result::GetTransactionsList(txs)) => txs
                .transactions
                .into_iter()
                .map(decode_raw_transaction)
                .collect::<Result<_>>(),
            _ => Err(ProtoClientError::InvalidResponse.into()),
        }
    }

    async fn get_transaction(&self, id: &ton_types::UInt256) -> Result<Option<RawTransaction>> {
        let data = rpc::Request {
            call: Some(rpc::request::Call::GetTransaction(
                rpc::request::GetTransaction {
                    id: Bytes::copy_from_slice(id.as_slice()),
                },
            )),
        };

        let req = external::ProtoRequest {
            data,
            requires_db: true,
        };

        let response = self.connection.post(req).await?;
        match response.result {
            Some(rpc::response::Result::GetRawTransaction(tx)) => match tx.transaction {
                Some(bytes) => Some(decode_raw_transaction(bytes)).transpose(),
                None => Ok(None),
            },
            _ => Err(ProtoClientError::InvalidResponse.into()),
        }
    }

    async fn get_dst_transaction(
        &self,
        message_hash: &ton_types::UInt256,
    ) -> Result<Option<RawTransaction>> {
        let data = rpc::Request {
            call: Some(rpc::request::Call::GetDstTransaction(
                rpc::request::GetDstTransaction {
                    message_hash: Bytes::copy_from_slice(message_hash.as_slice()),
                },
            )),
        };

        let req = external::ProtoRequest {
            data,
            requires_db: true,
        };

        let response = self.connection.post(req).await?;
        match response.result {
            Some(rpc::response::Result::GetRawTransaction(tx)) => match tx.transaction {
                Some(bytes) => Some(decode_raw_transaction(bytes)).transpose(),
                None => Ok(None),
            },
            _ => Err(ProtoClientError::InvalidResponse.into()),
        }
    }

    async fn get_latest_key_block(&self) -> Result<Block> {
        let data = rpc::Request {
            call: Some(rpc::request::Call::GetLatestKeyBlock(())),
        };

        let req = external::ProtoRequest {
            data,
            requires_db: true,
        };

        let response = self.connection.post(req).await?;
        match response.result {
            Some(rpc::response::Result::GetLatestKeyBlock(key_block)) => {
                Ok(Block::construct_from_bytes(key_block.block.as_ref())?)
            }
            _ => Err(ProtoClientError::InvalidResponse.into()),
        }
    }

    async fn get_capabilities(&self, clock: &dyn Clock) -> Result<NetworkCapabilities> {
        let (capabilities, _) = self
            .config_cache
            .get_blockchain_config(self, clock, false)
            .await?;
        Ok(capabilities)
    }

    async fn get_blockchain_config(
        &self,
        clock: &dyn Clock,
        force: bool,
    ) -> Result<ton_executor::BlockchainConfig> {
        let (_, config) = self
            .config_cache
            .get_blockchain_config(self, clock, force)
            .await?;
        Ok(config)
    }
}

fn decode_raw_transaction(bytes: Bytes) -> Result<RawTransaction> {
    let cell = ton_types::deserialize_tree_of_cells(&mut bytes.as_ref())?;
    let hash = cell.repr_hash();
    let data = ton_block::Transaction::construct_from_cell(cell)?;
    Ok(RawTransaction { hash, data })
}

#[derive(thiserror::Error, Copy, Clone, Debug)]
pub enum ProtoClientError {
    #[error("Failed to parse response")]
    InvalidResponse,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use futures_util::StreamExt;
    use nekoton_proto::models::ProtoAnswer;
    use nekoton_proto::prost::Message;

    use super::*;

    #[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
    #[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
    impl ProtoConnection for reqwest::Client {
        async fn post(&self, req: external::ProtoRequest) -> Result<rpc::Response> {
            println!("{req:?}");
            let response = self
                .post("https://jrpc.everwallet.net/proto")
                .body(req.data.encode_to_vec())
                .header("Content-Type", "application/x-protobuf")
                .send()
                .await?;

            match ProtoAnswer::parse_response(response).await? {
                ProtoAnswer::Result(response) => Ok(response),
                ProtoAnswer::Error(e) => anyhow::bail!(e.message)
            }
        }
    }

    #[tokio::test]
    async fn test_transactions_stream() -> Result<()> {
        let transport = ProtoTransport::new(Arc::new(reqwest::Client::new()));

        let mut from_lt = 30526271000007;
        let until_lt = 26005429000001;
        let test_address =
            "0:cd809fb1cde24b6d3cd4a3dd9102e10c0f73ddfa21c7118f233dc7309bbb0b73".parse()?;

        let mut transactions = crate::core::utils::request_transactions(
            &transport,
            &test_address,
            from_lt,
            Some(until_lt),
            2,
            None,
        );

        while let Some(transactions) = transactions.next().await {
            for transaction in transactions? {
                assert_eq!(transaction.data.lt, from_lt);
                from_lt = transaction.data.prev_trans_lt;
            }
        }

        assert_eq!(from_lt, until_lt);
        Ok(())
    }

    #[tokio::test]
    async fn test_connection() -> Result<()> {
        let transport = ProtoTransport::new(Arc::new(reqwest::Client::new()));
        let address = MsgAddressInt::from_str(
            "-1:3333333333333333333333333333333333333333333333333333333333333333",
        )?;
        transport.get_contract_state(&address).await?;

        let a = transport
            .get_transactions(&address, 0, 10)
            .await?;

        println!("LEN: {}", a.len());

        transport
            .get_transaction(&ton_types::UInt256::from_slice(
                &hex::decode("4a0a06bfbfaba4da8fcc7f5ad617fdee5344d954a1794e35618df2a4b349d15c")
                    .unwrap(),
            ))
            .await?.unwrap();

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

            // Rate limits
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        transport.get_latest_key_block().await?;

        Ok(())
    }
}
