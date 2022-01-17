use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use graphql_client::{GraphQLQuery, Response};
use ton_block::{Account, Deserializable, Message, MsgAddressInt, Serializable};

use nekoton_abi::{GenTimings, LastTransactionId, TransactionId};
use nekoton_utils::*;

use crate::core::models::ReliableBehavior;
use crate::external::GqlConnection;

use super::models::*;
use super::utils::ConfigCache;
use super::{Transport, TransportInfo};

pub struct GqlTransport {
    connection: Arc<dyn GqlConnection>,
    config_cache: ConfigCache,
}

impl GqlTransport {
    pub fn new(connection: Arc<dyn GqlConnection>) -> Self {
        let use_default_config = connection.is_local();

        Self {
            connection,
            config_cache: ConfigCache::new(use_default_config),
        }
    }

    async fn fetch<T>(&self, params: T::Variables) -> Result<T::ResponseData>
    where
        T: GraphQLQuery,
    {
        let request_body = T::build_query(params);
        let response = self
            .connection
            .post(&serde_json::to_string(&request_body).trust_me())
            .await
            .map_err(api_failure)?;

        match serde_json::from_str::<Response<T::ResponseData>>(&response) {
            Ok(response) => response.data.ok_or_else(|| invalid_response().into()),
            Err(e) => Err(api_failure(format!(
                "Failed parsing api response: {}. Response data: {}",
                e, response
            ))
            .into()),
        }
    }

    pub async fn get_latest_block(&self, addr: &MsgAddressInt) -> Result<LatestBlock> {
        let workchain_id = addr.get_workchain_id();

        let blocks = self
            .fetch::<QueryLatestMasterchainBlock>(query_latest_masterchain_block::Variables)
            .await?
            .blocks
            .ok_or_else(no_blocks_found)?;

        match blocks.into_iter().flatten().next() {
            Some(block) => {
                // Handle simple case when searched account is in masterchain
                if workchain_id == -1 {
                    return match (block.id, block.end_lt, block.gen_utime) {
                        (Some(id), Some(end_lt), Some(gen_utime)) => Ok(LatestBlock {
                            id,
                            end_lt: u64::from_str(&end_lt).unwrap_or_default(),
                            gen_utime: gen_utime as u32,
                        }),
                        _ => Err(no_blocks_found().into()),
                    };
                }

                // Find account's shard block
                let shards: Vec<_> = block
                    .master
                    .and_then(|master| master.shard_hashes)
                    .ok_or_else(no_blocks_found)?;

                // Find matching shard
                for item in shards.into_iter().flatten() {
                    match (item.workchain_id, item.shard) {
                        (Some(workchain_id), Some(shard)) => {
                            if check_shard_match(workchain_id, &shard, addr)? {
                                return item
                                    .descr
                                    .and_then(|descr| {
                                        Some(LatestBlock {
                                            id: descr.root_hash?,
                                            end_lt: u64::from_str(&descr.end_lt?)
                                                .unwrap_or_default(),
                                            gen_utime: descr.gen_utime? as u32,
                                        })
                                    })
                                    .ok_or_else(|| no_blocks_found().into());
                            }
                        }
                        _ => return Err(no_blocks_found().into()),
                    }
                }

                Err(no_blocks_found().into())
            }
            // Node SE case (without masterchain and sharding)
            None => {
                let block = self
                    .fetch::<QueryNodeSeConditions>(query_node_se_conditions::Variables {
                        workchain: workchain_id as i64,
                    })
                    .await?
                    .blocks
                    .and_then(|blocks| blocks.into_iter().flatten().next())
                    .ok_or_else(no_blocks_found)?;

                match (block.after_merge, &block.shard) {
                    (Some(after_merge), Some(shard))
                        if !after_merge && shard == "8000000000000000" => {}
                    // If workchain is sharded then it is not Node SE and missing masterchain blocks is error
                    _ => return Err(no_blocks_found().into()),
                }

                self.fetch::<QueryNodeSeLatestBlock>(query_node_se_latest_block::Variables {
                    workchain: workchain_id as i64,
                })
                .await?
                .blocks
                .and_then(|blocks| {
                    blocks.into_iter().flatten().next().and_then(|block| {
                        Some(LatestBlock {
                            id: block.id?,
                            end_lt: u64::from_str(&block.end_lt?).unwrap_or_default(),
                            gen_utime: block.gen_utime? as u32,
                        })
                    })
                })
                .ok_or_else(|| no_blocks_found().into())
            }
        }
    }

    pub async fn get_block(&self, id: &str) -> Result<ton_block::Block> {
        let boc = self
            .fetch::<QueryBlock>(query_block::Variables { id: id.to_owned() })
            .await?
            .blocks
            .and_then(|block| block.into_iter().flatten().next())
            .ok_or_else(no_blocks_found)?
            .boc
            .ok_or_else(invalid_response)?;

        ton_block::Block::construct_from_base64(&boc)
            .map_err(|_| NodeClientError::InvalidBlock.into())
    }

    pub async fn wait_for_next_block(
        &self,
        current: &str,
        addr: &MsgAddressInt,
        timeout: Duration,
    ) -> Result<String> {
        let timeout_ms = timeout.as_secs_f64() * 1000.0;

        let block = self
            .fetch::<QueryNextBlock>(query_next_block::Variables {
                id: current.to_owned(),
                timeout: timeout_ms,
            })
            .await?
            .blocks
            .and_then(|blocks| blocks.into_iter().flatten().next())
            .ok_or_else(no_blocks_found)?;

        let workchain_id = block.workchain_id.ok_or_else(invalid_response)?;
        let shard = block.shard.as_ref().ok_or_else(invalid_response)?;

        match (
            block.id,
            block.after_split,
            check_shard_match(workchain_id, shard, addr)?,
        ) {
            (Some(block_id), Some(true), false) => {
                let result = self
                    .fetch::<QueryBlockAfterSplit>(query_block_after_split::Variables {
                        block_id,
                        prev_id: current.to_owned(),
                        timeout: timeout_ms,
                    })
                    .await?
                    .blocks
                    .and_then(|block| block.into_iter().flatten().next())
                    .ok_or_else(no_blocks_found)?
                    .id
                    .ok_or_else(invalid_response)?;
                Ok(result)
            }
            (Some(block_id), _, _) => Ok(block_id),
            _ => Err(invalid_response().into()),
        }
    }
}

#[async_trait]
impl Transport for GqlTransport {
    fn info(&self) -> TransportInfo {
        TransportInfo {
            max_transactions_per_fetch: 50,
            reliable_behavior: ReliableBehavior::BlockWalking,
            has_key_blocks: !self.connection.is_local(),
        }
    }

    async fn send_message(&self, message: &Message) -> Result<()> {
        let cell = message
            .write_to_new_cell()
            .map_err(|_| NodeClientError::FailedToSerialize)?
            .into();

        let boc = base64::encode(
            ton_types::serialize_toc(&cell).map_err(|_| NodeClientError::FailedToSerialize)?,
        );
        let id = base64::encode(&cell.repr_hash());

        let _ = self
            .fetch::<MutationSendMessage>(mutation_send_message::Variables { id, boc })
            .await?;

        Ok(())
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        let account_state = match self
            .fetch::<QueryAccountState>(query_account_state::Variables {
                address: address.to_string(),
            })
            .await?
            .accounts
            .ok_or_else(invalid_response)?
            .into_iter()
            .next()
            .and_then(|item| item.and_then(|account| account.boc))
        {
            Some(account_state) => account_state,
            None => return Ok(RawContractState::NotExists),
        };

        match Account::construct_from_base64(&account_state) {
            Ok(Account::Account(account)) => {
                let last_transaction_id = LastTransactionId::Inexact {
                    latest_lt: account.storage.last_trans_lt,
                };

                Ok(RawContractState::Exists(ExistingContract {
                    account,
                    timings: GenTimings::Unknown,
                    last_transaction_id,
                }))
            }
            Ok(_) => Ok(RawContractState::NotExists),
            Err(_) => Err(NodeClientError::InvalidAccountState.into()),
        }
    }

    async fn get_accounts_by_code_hash(
        &self,
        code_hash: &ton_types::UInt256,
        limit: u8,
        continuation: &Option<MsgAddressInt>,
    ) -> Result<Vec<MsgAddressInt>> {
        self.fetch::<QueryAccountsByCodeHash>(query_accounts_by_code_hash::Variables {
            code_hash: code_hash.to_hex_string(),
            continuation: continuation.as_ref().map(ToString::to_string),
            limit: limit as i64,
        })
        .await?
        .accounts
        .ok_or_else(invalid_response)?
        .into_iter()
        .flatten()
        .flat_map(|item| item.id)
        .map(|account| ton_block::MsgAddressInt::from_str(&account))
        .collect()
    }

    async fn get_transactions(
        &self,
        address: MsgAddressInt,
        from: TransactionId,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        self.fetch::<QueryAccountTransactions>(query_account_transactions::Variables {
            address: address.to_string(),
            last_transaction_lt: from.lt.to_string(),
            limit: count as i64,
        })
        .await?
        .transactions
        .ok_or_else(invalid_response)?
        .into_iter()
        .flatten()
        .map(|transaction| {
            let bytes = base64::decode(&transaction.boc.ok_or_else(invalid_response)?)?;
            let cell = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(bytes))
                .map_err(|_| NodeClientError::InvalidTransaction)?;
            let hash = cell.repr_hash();
            Ok(RawTransaction {
                hash,
                data: ton_block::Transaction::construct_from_cell(cell)
                    .map_err(|_| NodeClientError::InvalidTransaction)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()
    }

    async fn get_transaction(&self, id: &ton_types::UInt256) -> Result<Option<RawTransaction>> {
        self.fetch::<QueryTransaction>(query_transaction::Variables {
            hash: id.to_hex_string(),
        })
        .await?
        .transactions
        .ok_or_else(invalid_response)?
        .into_iter()
        .flatten()
        .map(|transaction| {
            let bytes = base64::decode(&transaction.boc.ok_or_else(invalid_response)?)?;
            let cell = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(bytes))
                .map_err(|_| NodeClientError::InvalidTransaction)?;
            let hash = cell.repr_hash();
            Ok(RawTransaction {
                hash,
                data: ton_block::Transaction::construct_from_cell(cell)
                    .map_err(|_| NodeClientError::InvalidTransaction)?,
            })
        })
        .next()
        .transpose()
    }

    async fn get_latest_key_block(&self) -> Result<ton_block::Block> {
        let boc = self
            .fetch::<QueryLatestKeyBlock>(query_latest_key_block::Variables)
            .await?
            .blocks
            .and_then(|block| block.into_iter().flatten().next())
            .ok_or_else(no_blocks_found)?
            .boc
            .ok_or_else(invalid_response)?;

        let block = ton_block::Block::construct_from_base64(&boc)
            .map_err(|_| NodeClientError::InvalidBlock)?;
        Ok(block)
    }

    async fn get_blockchain_config(
        &self,
        clock: &dyn Clock,
    ) -> Result<ton_executor::BlockchainConfig> {
        self.config_cache.get_blockchain_config(self, clock).await
    }
}

#[derive(Clone, Debug)]
pub struct LatestBlock {
    pub id: String,
    pub end_lt: u64,
    pub gen_utime: u32,
}

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/query_block.graphql"
)]
struct QueryBlock;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/query_next_block.graphql"
)]
struct QueryNextBlock;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/query_block_after_split.graphql"
)]
struct QueryBlockAfterSplit;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/query_account_state.graphql"
)]
struct QueryAccountState;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/query_account_transactions.graphql"
)]
struct QueryAccountTransactions;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/query_transaction.graphql"
)]
struct QueryTransaction;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/query_accounts_by_code_hash.graphql"
)]
struct QueryAccountsByCodeHash;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/query_latest_masterchain_block.graphql"
)]
struct QueryLatestMasterchainBlock;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/query_latest_key_block.graphql"
)]
struct QueryLatestKeyBlock;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/query_node_se_conditions.graphql"
)]
struct QueryNodeSeConditions;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/query_node_se_latest_block.graphql"
)]
struct QueryNodeSeLatestBlock;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/transport/gql/schema.graphql",
    query_path = "src/transport/gql/mutation_send_message.graphql"
)]
struct MutationSendMessage;

fn check_shard_match(workchain_id: i64, shard: &str, addr: &MsgAddressInt) -> Result<bool> {
    let shard = u64::from_str_radix(shard, 16).map_err(|_| NodeClientError::NoBlocksFound)?;

    let ident = ton_block::ShardIdent::with_tagged_prefix(workchain_id as i32, shard)
        .map_err(api_failure)?;

    let prefix = ton_block::AccountIdPrefixFull::prefix(addr).map_err(api_failure)?;
    Ok(ident.contains_full_prefix(&prefix))
}

fn api_failure<T>(e: T) -> NodeClientError
where
    T: std::fmt::Display,
{
    NodeClientError::ApiFailure {
        reason: e.to_string(),
    }
}

fn invalid_response() -> NodeClientError {
    NodeClientError::InvalidResponse
}

fn no_blocks_found() -> NodeClientError {
    NodeClientError::NoBlocksFound
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum NodeClientError {
    #[error("API request failed. {reason}")]
    ApiFailure { reason: String },
    #[error("Invalid response")]
    InvalidResponse,
    #[error("Invalid transaction data")]
    InvalidTransaction,
    #[error("Failed to serialize data")]
    FailedToSerialize,
    #[error("Invalid account state")]
    InvalidAccountState,
    #[error("No blocks found")]
    NoBlocksFound,
    #[error("Unsupported network")]
    UnsupportedNetwork,
    #[error("Invalid block")]
    InvalidBlock,
    #[error("Invalid config")]
    InvalidConfig,
}
