use ton_block::{AccountStuff, Transaction};
use ton_types::UInt256;

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum ContractState {
    NotExists,
    Exists {
        account: AccountStuff,
        timings: GenTimings,
        last_transaction_id: TransactionId,
    },
}

#[derive(Debug, Copy, Clone)]
pub enum GenTimings {
    Unknown,
    Known { gen_lt: u64, gen_utime: u32 },
}

#[derive(Debug, Copy, Clone)]
pub struct TransactionId {
    pub lt: u64,
    pub hash: UInt256,
}

#[derive(Clone)]
pub struct TransactionFull {
    pub hash: UInt256,
    pub data: Transaction,
}
