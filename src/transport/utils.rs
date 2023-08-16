use std::sync::Arc;

use anyhow::Result;
use quick_cache::sync::Cache as QuickCache;
use tokio::sync::Mutex;

use nekoton_utils::*;

use super::models::RawContractState;
use super::Transport;
use crate::core::models::NetworkCapabilities;

#[allow(unused)]
pub struct AccountsCache {
    accounts: QuickCache<ton_block::MsgAddressInt, Arc<RawContractState>>,
}

impl Default for AccountsCache {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl AccountsCache {
    pub fn new() -> Self {
        const DEFAULT_ACCOUNTS_CAPACITY: usize = 100;

        Self::with_capacity(DEFAULT_ACCOUNTS_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            accounts: QuickCache::new(capacity),
        }
    }

    #[allow(unused)]
    pub fn get_account_state(
        &self,
        address: &ton_block::MsgAddressInt,
    ) -> Option<Arc<RawContractState>> {
        self.accounts.get(address)
    }

    #[allow(unused)]
    pub fn update_account_state(
        &self,
        address: &ton_block::MsgAddressInt,
        account: &RawContractState,
    ) {
        self.accounts
            .insert(address.clone(), Arc::new(account.clone()))
    }
}

pub struct ConfigCache {
    use_default_config: bool,
    state: Mutex<Option<ConfigCacheState>>,
}

impl ConfigCache {
    pub fn new(use_default_config: bool) -> Self {
        Self {
            use_default_config,
            state: Mutex::new(if use_default_config {
                Some(ConfigCacheState {
                    capabilities: NetworkCapabilities {
                        global_id: 0,
                        raw: 0,
                    },
                    config: ton_executor::BlockchainConfig::default(),
                    last_key_block_seqno: 0,
                    phase: ConfigCachePhase::WainingNextValidatorsSet { deadline: u32::MAX },
                })
            } else {
                None
            }),
        }
    }

    pub async fn get_blockchain_config(
        &self,
        transport: &dyn Transport,
        clock: &dyn Clock,
        force: bool,
    ) -> Result<(NetworkCapabilities, ton_executor::BlockchainConfig)> {
        let mut cache = self.state.lock().await;

        let now = clock.now_sec_u64() as u32;

        Ok(match &*cache {
            None => {
                let (capabilities, config, key_block_seqno) = fetch_config(transport).await?;
                let phase = compute_next_phase(now, &config, None, key_block_seqno)?;
                *cache = Some(ConfigCacheState {
                    capabilities,
                    config: config.clone(),
                    last_key_block_seqno: key_block_seqno,
                    phase,
                });
                (capabilities, config)
            }
            Some(a) if force && !self.use_default_config || cache_expired(now, a.phase) => {
                let (capabilities, config, key_block_seqno) = fetch_config(transport).await?;
                let phase = compute_next_phase(
                    now,
                    &config,
                    Some(a.last_key_block_seqno),
                    key_block_seqno,
                )?;
                *cache = Some(ConfigCacheState {
                    capabilities,
                    config: config.clone(),
                    last_key_block_seqno: key_block_seqno,
                    phase,
                });
                (capabilities, config)
            }
            Some(a) => (a.capabilities, a.config.clone()),
        })
    }
}

async fn fetch_config(
    transport: &dyn Transport,
) -> Result<(NetworkCapabilities, ton_executor::BlockchainConfig, u32)> {
    let block = transport.get_latest_key_block().await?;

    let info = block.info.read_struct()?;

    let extra = block
        .read_extra()
        .map_err(|_| QueryConfigError::InvalidBlock)?;

    let master = extra
        .read_custom()
        .map_err(|_| QueryConfigError::InvalidBlock)?
        .ok_or(QueryConfigError::InvalidBlock)?;

    let params = master
        .config()
        .ok_or(QueryConfigError::InvalidBlock)?
        .clone();

    let config = ton_executor::BlockchainConfig::with_config(params, block.global_id)
        .map_err(|_| QueryConfigError::InvalidConfig)?;

    let capabilities = NetworkCapabilities {
        global_id: block.global_id,
        raw: config.capabilites(),
    };

    Ok((capabilities, config, info.seq_no()))
}

fn compute_next_phase(
    now: u32,
    config: &ton_executor::BlockchainConfig,
    last_key_block_seqno: Option<u32>,
    fetched_key_block_seqno: u32,
) -> Result<ConfigCachePhase> {
    if matches!(last_key_block_seqno, Some(seqno) if fetched_key_block_seqno == seqno) {
        return Ok(ConfigCachePhase::WaitingKeyBlock);
    }

    let elector_params = config.raw_config().elector_params()?;
    let current_vset = config.raw_config().validator_set()?;

    let elections_end = current_vset.utime_until() - elector_params.elections_end_before;
    if now < elections_end {
        Ok(ConfigCachePhase::WaitingElectionsEnd {
            deadline: elections_end,
        })
    } else {
        Ok(ConfigCachePhase::WainingNextValidatorsSet {
            deadline: current_vset.utime_until(),
        })
    }
}

fn cache_expired(now: u32, phase: ConfigCachePhase) -> bool {
    match phase {
        ConfigCachePhase::WaitingKeyBlock => true,
        ConfigCachePhase::WaitingElectionsEnd { deadline }
        | ConfigCachePhase::WainingNextValidatorsSet { deadline } => now > deadline,
    }
}

struct ConfigCacheState {
    capabilities: NetworkCapabilities,
    config: ton_executor::BlockchainConfig,
    last_key_block_seqno: u32,
    phase: ConfigCachePhase,
}

#[derive(Copy, Clone)]
enum ConfigCachePhase {
    WaitingKeyBlock,
    WaitingElectionsEnd { deadline: u32 },
    WainingNextValidatorsSet { deadline: u32 },
}

#[derive(thiserror::Error, Debug)]
enum QueryConfigError {
    #[error("Invalid block")]
    InvalidBlock,
    #[error("Invalid config")]
    InvalidConfig,
}
