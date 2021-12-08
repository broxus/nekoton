use serde::{Deserialize, Serialize};

use nekoton_abi::TransactionId;
use nekoton_utils::*;

#[derive(Serialize)]
pub struct GetContractState<'a> {
    #[serde(with = "serde_address")]
    pub address: &'a ton_block::MsgAddressInt,
}

#[derive(Serialize)]
pub struct SendMessage<'a> {
    #[serde(with = "serde_message")]
    pub message: &'a ton_block::Message,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum GetContractStateResponse {
    NotExists,
    Exists(GetContractStateResponseData),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetContractStateResponseData {
    #[serde(with = "serde_ton_block")]
    pub account: ton_block::AccountStuff,
    pub timings: GetContractStateResponseTimings,
    pub last_transaction_id: TransactionId,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct GetContractStateResponseTimings {
    #[serde(with = "serde_string")]
    pub gen_lt: u64,
    pub gen_utime: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdnlRpcGetTransactions<'a> {
    #[serde(with = "serde_address")]
    pub address: &'a ton_block::MsgAddressInt,
    pub transaction_id: Option<TransactionId>,
    pub count: u8,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AdnlRpcGetTransactionsResponse {
    #[serde(with = "serde_bytes_base64")]
    pub transactions: Vec<u8>,
}

#[derive(Serialize)]
pub struct ExplorerGetTransactions<'a> {
    pub limit: u64,

    #[serde(default, with = "serde_optional_string")]
    pub last_transaction_lt: Option<u64>,

    #[serde(with = "serde_address")]
    pub account: &'a ton_block::MsgAddressInt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBlockResponse {
    #[serde(with = "serde_ton_block")]
    pub block: ton_block::Block,
}
