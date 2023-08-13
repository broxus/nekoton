use std::sync::Arc;

use anyhow::Result;
use ton_block::{Block, Deserializable, MsgAddressInt, Serializable};
use nekoton_proto::prost::bytes::Bytes;
use nekoton_proto::rpc;
use nekoton_proto::utils;
use nekoton_proto::utils::{addr_to_bytes, bytes_to_addr};

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
            }))
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
            Some(rpc::response::Result::GetContractState(state))=> match state.contract_state {
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
                rpc::request::GetAccountsByCodeHash { code_hash: code_hash.into_vec().into() , continuation: continuation.as_ref().map(addr_to_bytes), limit: limit as u32 },
            )),
        };

        let req = external::ProtoRequest {
            data,
            requires_db: false,
        };

        let response = self.connection.post(req).await?;
        match response.result {
            Some(rpc::response::Result::GetAccounts(accounts)) => accounts.account
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
            Some(rpc::response::Result::GetLatestKeyBlock(key_block)) => Ok(
                Block::construct_from_bytes(key_block.block.as_ref())?,
            ),
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
