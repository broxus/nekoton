use crate::core::models::{
    ContractState, GenTimings, LastTransactionId, PendingTransaction, TransactionId,
};
use crate::utils::serde_ton_block;
use serde::{Deserialize, Serialize};
use ton_block::{AccountStuff, Transaction};
use ton_types::UInt256;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum RawContractState {
    NotExists,
    Exists(ExistingContract),
}

impl RawContractState {
    pub fn brief(&self) -> ContractState {
        match self {
            Self::NotExists => ContractState::default(),
            Self::Exists(state) => state.brief(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExistingContract {
    #[serde(with = "serde_ton_block")]
    pub account: AccountStuff,
    pub timings: GenTimings,
    pub last_transaction_id: LastTransactionId,
}

impl ExistingContract {
    pub fn brief(&self) -> ContractState {
        ContractState {
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
pub struct RawTransaction {
    pub hash: UInt256,
    pub data: Transaction,
}

impl RawTransaction {
    pub fn id(&self) -> TransactionId {
        TransactionId {
            lt: self.data.lt,
            hash: self.hash,
        }
    }
}

impl PartialEq<RawTransaction> for PendingTransaction {
    fn eq(&self, other: &RawTransaction) -> bool {
        if other.data.now >= self.expire_at {
            return false;
        }

        match other
            .data
            .in_msg
            .as_ref()
            .and_then(|msg| msg.read_struct().ok())
        {
            Some(message) if self.src == message.src() => {
                let body_hash = message
                    .body()
                    .map(|body| body.into_cell().repr_hash())
                    .unwrap_or_default();

                self.body_hash == body_hash
            }
            _ => false,
        }
    }
}
