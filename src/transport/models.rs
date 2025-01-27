use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use ton_block::{Account, AccountStuff, Transaction};
use ton_types::UInt256;

use crate::models::{ContractState, PendingTransaction};
use nekoton_abi::{ExecutionContext, GenTimings, LastTransactionId};
use nekoton_utils::{serde_account_stuff, Clock};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum RawContractState {
    NotExists { timings: GenTimings },
    Exists(ExistingContract),
}

impl RawContractState {
    pub fn brief(&self) -> ContractState {
        match self {
            Self::NotExists { .. } => ContractState::default(),
            Self::Exists(state) => state.brief(),
        }
    }

    pub fn into_account(self) -> Account {
        match self {
            Self::NotExists { .. } => Account::AccountNone,
            Self::Exists(state) => Account::Account(state.account),
        }
    }

    pub fn into_contract(self) -> Option<ExistingContract> {
        match self {
            Self::NotExists { .. } => None,
            Self::Exists(contract) => Some(contract),
        }
    }

    pub fn update_timings(&mut self, new_timings: GenTimings) {
        match self {
            Self::NotExists { timings } => *timings = new_timings,
            Self::Exists(state) => state.timings = new_timings,
        }
    }

    pub fn last_known_trans_lt(&self) -> Option<u64> {
        let timings = match self {
            Self::NotExists { timings } => timings,
            Self::Exists(contract) => &contract.timings,
        };
        match timings {
            GenTimings::Known { gen_lt, .. } => Some(*gen_lt),
            GenTimings::Unknown => None,
        }
    }
}

impl From<RawContractState> for Option<ExistingContract> {
    fn from(state: RawContractState) -> Self {
        state.into_contract()
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum PollContractState {
    Unchanged { timings: GenTimings },
    NotExists { timings: GenTimings },
    Exists(ExistingContract),
}

impl PollContractState {
    pub fn to_changed(self) -> Result<RawContractState, GenTimings> {
        match self {
            Self::Exists(state) => Ok(RawContractState::Exists(state)),
            Self::NotExists { timings } => Ok(RawContractState::NotExists { timings }),
            Self::Unchanged { timings } => Err(timings),
        }
    }
}

impl From<RawContractState> for PollContractState {
    fn from(value: RawContractState) -> Self {
        match value {
            RawContractState::Exists(state) => Self::Exists(state),
            RawContractState::NotExists { timings } => Self::NotExists { timings },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExistingContract {
    #[serde(with = "serde_account_stuff")]
    pub account: AccountStuff,
    pub timings: GenTimings,
    pub last_transaction_id: LastTransactionId,
}

impl ExistingContract {
    pub fn brief(&self) -> ContractState {
        ContractState {
            last_lt: self.account.storage.last_trans_lt,
            balance: self.account.storage.balance.grams.as_u128(),
            gen_timings: self.timings,
            last_transaction_id: Some(self.last_transaction_id),
            is_deployed: matches!(
                self.account.storage.state,
                ton_block::AccountState::AccountActive { .. }
            ),
            code_hash: match &self.account.storage.state {
                ton_block::AccountState::AccountActive { state_init, .. } => {
                    state_init.code.as_ref().map(ton_types::Cell::repr_hash)
                }
                _ => None,
            },
        }
    }

    pub fn as_context<'a>(&'a self, clock: &'a dyn Clock) -> ExecutionContext<'a> {
        ExecutionContext {
            clock,
            account_stuff: &self.account,
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

impl PartialOrd for ExistingContract {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.account
            .storage
            .last_trans_lt
            .partial_cmp(&other.account.storage.last_trans_lt)
    }
}

#[derive(Clone, Debug)]
pub struct RawTransaction {
    pub hash: UInt256,
    pub data: Transaction,
}

impl PartialEq for RawTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.data.lt == other.data.lt && self.hash == other.hash
    }
}

impl Eq for RawTransaction {}

impl PartialOrd for RawTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RawTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.lt.cmp(&other.data.lt)
    }
}

impl PartialEq<RawTransaction> for PendingTransaction {
    fn eq(&self, other: &RawTransaction) -> bool {
        if other.data.now >= self.expire_at {
            return false;
        }

        matches!(
            other.data.in_msg.as_ref().map(|msg| msg.cell().repr_hash()),
            Some(message_hash) if self.message_hash == message_hash
        )
    }
}
