use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use ton_block::{Account, Deserializable, Message, MsgAddressInt, Serializable};

use nekoton_abi::{GenTimings, LastTransactionId};
use nekoton_utils::*;

use crate::core::models::{NetworkCapabilities, ReliableBehavior};
use crate::external::{GqlConnection, GqlRequest};

use self::queries::*;
use super::models::*;
use super::utils::{ConfigCache, ConfigResponse};
use super::{Transport, TransportInfo};

mod queries;

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
        T: GqlQuery,
    {
        let request_body = serde_json::to_string(&T::build_query(&params)).trust_me();
        let response = self
            .connection
            .post(GqlRequest {
                data: request_body,
                long_query: T::LONG_QUERY,
            })
            .await
            .map_err(api_failure)?;

        #[derive(Deserialize)]
        pub struct Response<T> {
            pub data: Option<T>,
        }

        match serde_json::from_str::<Response<T::ResponseData>>(&response) {
            Ok(response) => response.data.ok_or_else(|| invalid_response().into()),
            Err(e) => Err(api_failure(format!(
                "Failed parsing api response: {e}. Response data: {response}"
            ))
            .into()),
        }
    }

    pub async fn get_latest_block(&self, addr: &MsgAddressInt) -> Result<LatestBlock> {
        let workchain_id = addr.get_workchain_id();

        let block = self
            .fetch::<QueryLatestMasterchainBlock>(())
            .await?
            .blocks
            .into_iter()
            .next();

        match block {
            Some(block) => {
                // Handle simple case when searched account is in masterchain
                if workchain_id == -1 {
                    return Ok(LatestBlock {
                        id: block.id,
                        end_lt: parse_lt(&block.end_lt)?,
                        gen_utime: block.gen_utime as u32,
                    });
                }

                // Find matching shard
                for item in block.master.shard_hashes {
                    if check_shard_match(item.workchain_id, &item.shard, addr)? {
                        return Ok(LatestBlock {
                            id: item.descr.root_hash,
                            end_lt: parse_lt(&item.descr.end_lt)?,
                            gen_utime: item.descr.gen_utime as u32,
                        });
                    }
                }

                Err(no_blocks_found().into())
            }
            // Node SE case (without masterchain and sharding)
            None => {
                let blocks = self
                    .fetch::<QueryNodeSeConditions>(query_node_se_conditions::Variables {
                        workchain: workchain_id,
                    })
                    .await?
                    .blocks;
                let block = blocks.into_iter().next().ok_or_else(no_blocks_found)?;

                // If workchain is sharded then it is not Node SE and missing masterchain blocks is error
                if block.after_merge || block.shard != "8000000000000000" {
                    return Err(no_blocks_found().into());
                }

                let blocks = self
                    .fetch::<QueryNodeSeLatestBlock>(query_node_se_latest_block::Variables {
                        workchain: workchain_id,
                    })
                    .await?
                    .blocks;
                let block = blocks.into_iter().next().ok_or_else(no_blocks_found)?;

                Ok(LatestBlock {
                    id: block.id,
                    end_lt: parse_lt(&block.end_lt)?,
                    gen_utime: block.gen_utime as u32,
                })
            }
        }
    }

    pub async fn get_block(&self, id: &str) -> Result<ton_block::Block> {
        let blocks = self
            .fetch::<QueryBlock>(query_block::Variables { id: id.to_owned() })
            .await?
            .blocks;
        let boc = blocks.into_iter().next().ok_or_else(no_blocks_found)?.boc;

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

        let blocks = self
            .fetch::<QueryNextBlock>(query_next_block::Variables {
                id: current.to_owned(),
                timeout: timeout_ms,
            })
            .await?
            .blocks;
        let block = blocks.into_iter().next().ok_or_else(no_blocks_found)?;

        let block_id =
            if block.after_split && !check_shard_match(block.workchain_id, &block.shard, addr)? {
                let blocks = self
                    .fetch::<QueryBlockAfterSplit>(query_block_after_split::Variables {
                        block_id: block.id,
                        prev_id: current.to_owned(),
                        timeout: timeout_ms,
                    })
                    .await?
                    .blocks;
                blocks.into_iter().next().ok_or_else(no_blocks_found)?.id
            } else {
                block.id
            };

        Ok(block_id)
    }

    async fn fetch_config(&self) -> Result<ConfigResponse> {
        let block = self.get_latest_key_block().await?;
        let seqno = block.info.read_struct()?.seq_no();
        let extra = block.read_extra()?;
        let master = extra.read_custom()?.context("invalid key block")?;
        let config = master.config().context("invalid key block")?.clone();

        Ok(ConfigResponse {
            global_id: block.global_id,
            seqno,
            config,
        })
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
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
            .and_then(ton_types::BuilderData::into_cell)
            .map_err(|_| NodeClientError::FailedToSerialize)?;

        let boc = base64::encode(
            ton_types::serialize_toc(&cell).map_err(|_| NodeClientError::FailedToSerialize)?,
        );
        let id = base64::encode(cell.repr_hash());

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
            .into_iter()
            .next()
            .and_then(|state| state.boc)
        {
            Some(boc) => boc,
            None => {
                return Ok(RawContractState::NotExists {
                    timings: GenTimings::Unknown,
                })
            }
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
            Ok(_) => Ok(RawContractState::NotExists {
                timings: GenTimings::Unknown,
            }),
            Err(_) => Err(NodeClientError::InvalidAccountState.into()),
        }
    }

    async fn poll_contract_state(
        &self,
        address: &MsgAddressInt,
        _last_trans_lt: u64,
    ) -> Result<PollContractState> {
        // TODO: use two queries for state and status
        let state = self.get_contract_state(address).await?;
        Ok(PollContractState::from(state))
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
            limit,
        })
        .await?
        .accounts
        .into_iter()
        .map(|account| MsgAddressInt::from_str(&account.id))
        .collect()
    }

    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from_lt: u64,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        self.fetch::<QueryAccountTransactions>(query_account_transactions::Variables {
            address: address.to_string(),
            last_transaction_lt: from_lt.to_string(),
            limit: count,
        })
        .await?
        .transactions
        .into_iter()
        .map(|transaction| {
            let bytes = base64::decode(transaction.boc)?;
            let cell = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())
                .map_err(|_| NodeClientError::InvalidTransaction)?;
            let hash = cell.repr_hash();
            Ok(RawTransaction {
                hash,
                data: ton_block::Transaction::construct_from_cell(cell)
                    .map_err(|_| NodeClientError::InvalidTransaction)?,
            })
        })
        .collect()
    }

    async fn get_transaction(&self, id: &ton_types::UInt256) -> Result<Option<RawTransaction>> {
        self.fetch::<QueryTransaction>(query_transaction::Variables {
            hash: id.to_hex_string(),
        })
        .await?
        .transactions
        .into_iter()
        .map(|transaction| {
            let bytes = base64::decode(transaction.boc)?;
            let cell = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())
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

    async fn get_dst_transaction(
        &self,
        message_hash: &ton_types::UInt256,
    ) -> Result<Option<RawTransaction>> {
        self.fetch::<QueryDstTransaction>(query_dst_transaction::Variables {
            hash: message_hash.to_hex_string(),
        })
        .await?
        .transactions
        .into_iter()
        .map(|transaction| {
            let bytes = base64::decode(transaction.boc)?;
            let cell = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())
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
        let blocks = self.fetch::<QueryLatestKeyBlock>(()).await?.blocks;
        let boc = blocks.into_iter().next().ok_or_else(no_blocks_found)?.boc;

        ton_block::Block::construct_from_base64(&boc)
            .map_err(|_| NodeClientError::InvalidBlock.into())
    }

    async fn get_capabilities(&self, clock: &dyn Clock) -> Result<NetworkCapabilities> {
        let (capabilities, _) = self
            .config_cache
            .get_blockchain_config(clock, false, || self.fetch_config())
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
            .get_blockchain_config(clock, force, || self.fetch_config())
            .await?;
        Ok(config)
    }
}

#[derive(Clone, Debug)]
pub struct LatestBlock {
    pub id: String,
    pub end_lt: u64,
    pub gen_utime: u32,
}

fn check_shard_match(workchain_id: i32, shard: &str, addr: &MsgAddressInt) -> Result<bool> {
    let shard = u64::from_str_radix(shard, 16)?;

    let ident =
        ton_block::ShardIdent::with_tagged_prefix(workchain_id, shard).map_err(api_failure)?;

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

fn parse_lt(lt: &str) -> Result<u64, std::num::ParseIntError> {
    match lt.strip_prefix("0x") {
        Some(lt) => u64::from_str_radix(lt, 16),
        None => u64::from_str(lt),
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
    #[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
    impl GqlConnection for reqwest::Client {
        fn is_local(&self) -> bool {
            false
        }

        async fn post(&self, req: GqlRequest) -> Result<String> {
            println!("{req:?}");
            let text = self
                .post("https://mainnet.evercloud.dev/57a5b802e303424fb0078f612a4fbe35/graphql")
                .body(req.data)
                .header("Content-Type", "application/json")
                .send()
                .await?
                .text()
                .await?;
            // println!("{text}");
            Ok(text)
        }
    }

    #[tokio::test]
    async fn test_connection() {
        let transport = GqlTransport::new(Arc::new(reqwest::Client::new()));
        let address = MsgAddressInt::from_str(
            "-1:3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap();
        let base_wc_address = MsgAddressInt::from_str(
            "0:3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap();

        transport.send_message(&Message::default()).await.unwrap();

        transport.get_contract_state(&address).await.unwrap();
        transport
            .get_transactions(&address, 21968513000000, 10)
            .await
            .unwrap();

        transport.get_latest_block(&address).await.unwrap();
        transport.get_latest_block(&base_wc_address).await.unwrap();

        transport
            .get_transaction(&ton_types::UInt256::from_slice(
                &hex::decode("4a0a06bfbfaba4da8fcc7f5ad617fdee5344d954a1794e35618df2a4b349d15c")
                    .unwrap(),
            ))
            .await
            .unwrap()
            .unwrap();

        let setcode_multisig_code_hash = ton_types::UInt256::from_str(
            "e2b60b6b602c10ced7ea8ede4bdf96342c97570a3798066f3fb50a4b2b27a208",
        )
        .unwrap();

        let mut continuation = None;
        loop {
            let contracts = transport
                .get_accounts_by_code_hash(&setcode_multisig_code_hash, 50, &continuation)
                .await
                .unwrap();

            continuation = contracts.last().cloned();
            if continuation.is_none() {
                break;
            }
        }

        transport.get_latest_key_block().await.unwrap();
    }
}
