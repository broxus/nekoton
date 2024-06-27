use std::sync::Arc;

use anyhow::Result;
use futures_util::Future;
use quick_cache::sync::Cache as QuickCache;
use tokio::sync::Mutex;

use nekoton_utils::*;

use super::models::RawContractState;
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
    min_cache_for: Option<u32>,
    state: Mutex<Option<ConfigCacheState>>,
}

impl ConfigCache {
    pub fn new(use_default_config: bool) -> Self {
        // TODO: Move to params or connection config
        const MIN_CACHE_FOR: u32 = 60;

        Self {
            use_default_config,
            min_cache_for: Some(MIN_CACHE_FOR),
            state: Mutex::new(if use_default_config {
                Some(ConfigCacheState {
                    capabilities: NetworkCapabilities {
                        global_id: 0,
                        raw: 0,
                    },
                    config: ton_executor::BlockchainConfig::default(),
                    last_key_block_seqno: 0,
                    updated_at: 0,
                    phase: ConfigCachePhase::WainingNextValidatorsSet { deadline: u32::MAX },
                })
            } else {
                None
            }),
        }
    }

    pub async fn get_blockchain_config<F, Fut>(
        &self,
        clock: &dyn Clock,
        force: bool,
        f: F,
    ) -> Result<(NetworkCapabilities, ton_executor::BlockchainConfig)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<ConfigResponse>>,
    {
        let mut cache = self.state.lock().await;

        let now = clock.now_sec_u64() as u32;

        Ok(match &*cache {
            None => {
                let (capabilities, config, key_block_seqno) = fetch_config(f).await?;
                let phase = compute_next_phase(now, &config, None, key_block_seqno)?;
                *cache = Some(ConfigCacheState {
                    capabilities,
                    config: config.clone(),
                    last_key_block_seqno: key_block_seqno,
                    updated_at: now,
                    phase,
                });
                (capabilities, config)
            }
            Some(a) if force && !self.use_default_config || self.cache_expired(now, a) => {
                let (capabilities, config, key_block_seqno) = fetch_config(f).await?;
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
                    updated_at: now,
                    phase,
                });
                (capabilities, config)
            }
            Some(a) => (a.capabilities, a.config.clone()),
        })
    }

    fn cache_expired(&self, now: u32, state: &ConfigCacheState) -> bool {
        if let Some(min_cache_for) = self.min_cache_for {
            if now <= state.updated_at.saturating_add(min_cache_for) {
                return false;
            }
        }

        match state.phase {
            ConfigCachePhase::WaitingKeyBlock => true,
            ConfigCachePhase::WaitingElectionsEnd { deadline }
            | ConfigCachePhase::WainingNextValidatorsSet { deadline } => now > deadline,
        }
    }
}

async fn fetch_config<F, Fut>(
    f: F,
) -> Result<(NetworkCapabilities, ton_executor::BlockchainConfig, u32)>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<ConfigResponse>>,
{
    let res = f().await?;

    let config = ton_executor::BlockchainConfig::with_config(res.config, res.global_id)
        .map_err(|_| QueryConfigError::InvalidConfig)?;

    let capabilities = NetworkCapabilities {
        global_id: res.global_id,
        raw: config.capabilites(),
    };

    Ok((capabilities, config, res.seqno))
}

pub struct ConfigResponse {
    pub global_id: i32,
    pub seqno: u32,
    pub config: ton_block::ConfigParams,
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

struct ConfigCacheState {
    capabilities: NetworkCapabilities,
    config: ton_executor::BlockchainConfig,
    last_key_block_seqno: u32,
    updated_at: u32,
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
    #[error("Invalid config")]
    InvalidConfig,
}
