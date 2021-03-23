use ton_block::{AccountStuff, Transaction};
use ton_types::UInt256;

use crate::core::models::{GenTimings, TransactionId};

#[derive(Clone)]
pub enum ContractState {
    NotExists,
    Exists {
        account: AccountStuff,
        timings: GenTimings,
        last_transaction_id: TransactionId,
    },
}

#[derive(Clone)]
pub struct TransactionFull {
    pub hash: UInt256,
    pub data: Transaction,
}
