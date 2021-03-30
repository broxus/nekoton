mod abi;
mod compiled;

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use anyhow::Result;
use ton_block::{Account, Transaction};
use ton_executor::{BlockchainConfig, OrdinaryTransactionExecutor, TransactionExecutor};
use ton_types::Cell;

use crate::core::models::{GenTimings, LastTransactionId};
use crate::transport::models::ContractState;

use crate::utils::NoFailure;

fn match_contract_state(state: &ContractState) -> (Account, u32, u64, Arc<AtomicU64>) {
    match state {
        ContractState::NotExists => {
            let ac = Account::AccountNone;
            let block_unix_time = chrono::Utc::now().timestamp() as u32;
            let block_lt = 1;
            let last_tx_lt = Arc::new(AtomicU64::new(1));
            (ac, block_unix_time, block_lt, last_tx_lt)
        }
        ContractState::Exists {
            account,
            timings,
            last_transaction_id,
        } => {
            let ac = Account::Account(account.clone());
            let (block_unix_time, block_lt) = match timings {
                GenTimings::Unknown => (chrono::Utc::now().timestamp() as u32, 1),
                GenTimings::Known { gen_lt, gen_utime } => (*gen_utime, *gen_lt),
            };
            let last_tx_lt = match last_transaction_id {
                LastTransactionId::Exact(id) => id.lt,
                LastTransactionId::Inexact { latest_lt } => *latest_lt,
            };
            let last_tx_lt = Arc::new(AtomicU64::new(last_tx_lt));
            (ac, block_unix_time, block_lt, last_tx_lt)
        }
    }
}
