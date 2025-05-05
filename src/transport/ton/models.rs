use nekoton_utils::{
    serde_base64_address, serde_base64_uint256, serde_cell, serde_optional_base64_array,
    serde_transaction_array, serde_u128, serde_u64,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ton_block::VarUInteger7;
use ton_types::{Cell, UInt256};

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LatestBlock {
    pub last: BlockId,
    pub init: Init,
    #[serde(with = "serde_optional_base64_array")]
    pub state_root_hash: Option<[u8; 32]>,
    pub now: u32,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BlockId {
    #[serde(with = "serde_base64_uint256")]
    pub root_hash: UInt256,
    #[serde(with = "serde_base64_uint256")]
    pub file_hash: UInt256,
    pub seqno: u32,
    //#[serde(with = "serde_string_to_u64")]
    pub shard: String,
    pub workchain: i32,
    #[serde(default)]
    pub transactions: Vec<Transaction>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Init {
    #[serde(with = "serde_base64_uint256")]
    pub root_hash: UInt256,
    #[serde(with = "serde_base64_uint256")]
    pub file_hash: UInt256,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FullBlock {
    pub exist: bool,
    pub block: Option<ShardInfo>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ShardInfo {
    pub shards: Vec<BlockId>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(with = "serde_base64_address")]
    pub account: ton_block::MsgAddressInt,
    #[serde(with = "serde_base64_uint256")]
    pub hash: UInt256,
    #[serde(with = "serde_u64")]
    pub lt: u64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AccountStateResult {
    pub account: AccountInfo,
    pub block: BlockId,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum AccountState {
    #[serde(rename = "active")]
    Active {
        #[serde(with = "serde_cell")]
        code: Cell,
        #[serde(with = "serde_cell")]
        data: Cell,
    },

    #[serde(rename = "frozen")]
    Frozen {
        #[serde(rename = "state_hash", with = "serde_base64_uint256")]
        state_init_hash: UInt256,
    },

    #[serde(rename = "uninit")]
    Uninit,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub state: AccountState,
    pub balance: AccountBalance,
    pub storage_stat: StorageStat,
    #[serde(rename = "last")]
    pub last_transaction: Option<LastTransaction>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StorageStat {
    pub last_paid: u32,
    pub used: StorageUsed,
    #[serde(default)]
    pub due_payment: Option<u128>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct StorageUsed {
    pub cells: u64,
    pub bits: u64,
    pub public_cells: u64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AccountBalance {
    #[serde(with = "serde_u128")]
    pub coins: u128,
    #[serde(default)]
    pub currencies: Option<HashMap<u32, u128>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LastTransaction {
    #[serde(with = "serde_base64_uint256")]
    pub hash: UInt256,
    #[serde(with = "serde_u64")]
    pub lt: u64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AccountChangedResult {
    pub changed: bool,
    pub block: BlockId,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConfigResult {
    pub exist: bool,
    pub config: Option<ConfigInfo>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ConfigInfo {
    #[serde(with = "serde_cell")]
    pub cell: Cell,
    #[serde(with = "serde_base64_address")]
    pub address: ton_block::MsgAddressInt,
    pub global_balance: AccountBalance,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AccountTransactionsResult {
    pub blocks: Vec<BlockId>,
    #[serde(rename = "boc", with = "serde_transaction_array")]
    pub transactions: Vec<ton_block::Transaction>,
}

#[derive(Serialize, Debug)]
pub struct MessageBoc {
    pub boc: String,
}
