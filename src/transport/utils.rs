use tokio::sync::Mutex;

use anyhow::Result;

use super::Transport;
use crate::utils::NoFailure;

#[derive(Default)]
pub struct ConfigCache {
    state: Mutex<Option<ConfigCacheState>>,
}

impl ConfigCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_blockchain_config(
        &self,
        transport: &dyn Transport,
    ) -> Result<ton_executor::BlockchainConfig> {
        let mut cache = self.state.lock().await;

        let now = chrono::Utc::now().timestamp() as u32;

        Ok(match &*cache {
            None => {
                let (config, key_block_seqno) = fetch_config(transport).await?;
                let phase = compute_next_phase(now, &config, None, key_block_seqno)?;
                *cache = Some(ConfigCacheState {
                    config: config.clone(),
                    last_key_block_seqno: key_block_seqno,
                    phase,
                });
                config
            }
            Some(a) if cache_expired(now, a.phase) => {
                let (config, key_block_seqno) = fetch_config(transport).await?;
                let phase = compute_next_phase(
                    now,
                    &config,
                    Some(a.last_key_block_seqno),
                    key_block_seqno,
                )?;
                *cache = Some(ConfigCacheState {
                    config: config.clone(),
                    last_key_block_seqno: key_block_seqno,
                    phase,
                });
                config
            }
            Some(a) => a.config.clone(),
        })
    }
}

async fn fetch_config(transport: &dyn Transport) -> Result<(ton_executor::BlockchainConfig, u32)> {
    let block = transport.get_latest_key_block().await?;

    let info = block.info.read_struct().convert()?;

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

    let config = ton_executor::BlockchainConfig::with_config(params)
        .map_err(|_| QueryConfigError::InvalidConfig)?;

    Ok((config, info.seq_no()))
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

    let elector_params = config.raw_config().elector_params().convert()?;
    let current_vset = config.raw_config().validator_set().convert()?;

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
