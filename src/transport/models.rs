#[derive(Debug, Clone)]
pub struct LastBlockIdExt {
    pub workchain: i8,
    pub shard: u64,
    pub seqno: u32,
    pub root_hash: [u8; 32],
    pub file_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub enum AccountState {
    NotFound,
    Frozen,
    Active(ActiveAccountState),
}

#[derive(Debug, Clone)]
pub struct ActiveAccountState {
    pub last_trans_id: TransactionId,
    pub gen_lt: u64,
    pub gen_utime: u32,
    pub balance: u64,
}

#[derive(Debug, Clone)]
pub struct TransactionId {
    pub lt: u64,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub id: TransactionId,
    pub prev_trans_lt: Option<TransactionId>,
    pub now: u32,
}
