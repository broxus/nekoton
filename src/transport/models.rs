use ton_block::{AccountStuff, Transaction};
use ton_types::UInt256;

use crate::core::models::{AccountState, GenTimings, LastTransactionId};

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum ContractState {
    NotExists,
    Exists(ExistingContract),
}

#[derive(Clone)]
pub struct ExistingContract {
    pub account: AccountStuff,
    pub timings: GenTimings,
    pub last_transaction_id: LastTransactionId,
}

impl ExistingContract {
    pub fn account_state(&self) -> AccountState {
        AccountState {
            balance: self.account.storage.balance.grams.0 as u64,
            gen_timings: self.timings,
            last_transaction_id: Some(self.last_transaction_id),
            is_deployed: matches!(
                self.account.storage.state,
                ton_block::AccountState::AccountActive(_)
            ),
        }
    }
}

#[derive(Clone)]
pub struct TransactionFull {
    pub hash: UInt256,
    pub data: Transaction,
}
