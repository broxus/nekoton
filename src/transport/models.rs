use ton_block::{AccountStuff, Transaction};
use ton_types::UInt256;

use crate::core::models::{
    AccountState, GenTimings, LastTransactionId, PendingTransaction, TransactionId,
};

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq)]
pub enum ContractState {
    NotExists,
    Exists(ExistingContract),
}

impl ContractState {
    pub fn account_state(&self) -> AccountState {
        match self {
            Self::NotExists => AccountState::default(),
            Self::Exists(state) => state.account_state(),
        }
    }
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

impl PartialEq for ExistingContract {
    fn eq(&self, other: &Self) -> bool {
        self.account
            .storage
            .last_trans_lt
            .eq(&other.account.storage.last_trans_lt)
    }
}

#[derive(Clone)]
pub struct TransactionFull {
    pub hash: UInt256,
    pub data: Transaction,
}

impl TransactionFull {
    pub fn id(&self) -> TransactionId {
        TransactionId {
            lt: self.data.lt,
            hash: self.hash,
        }
    }
}

impl PartialEq<TransactionFull> for PendingTransaction {
    fn eq(&self, other: &TransactionFull) -> bool {
        if self.expire_at >= other.data.now {
            return false;
        }

        match other
            .data
            .in_msg
            .as_ref()
            .and_then(|msg| msg.read_struct().ok())
        {
            Some(msg) if self.src == msg.src() => {
                let body_hash = msg
                    .body()
                    .map(|body| body.hash(ton_types::MAX_LEVEL))
                    .unwrap_or_default();

                self.body_hash == body_hash
            }
            _ => false,
        }
    }
}
