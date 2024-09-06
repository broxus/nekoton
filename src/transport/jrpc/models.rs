use serde::{Deserialize, Serialize};

use nekoton_utils::*;

#[derive(Serialize)]
pub struct GetContractState<'a> {
    #[serde(with = "serde_address")]
    pub address: &'a ton_block::MsgAddressInt,

    #[serde(default, with = "serde_optional_string")]
    pub last_transaction_lt: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAccountsByCodeHash<'a> {
    pub limit: u32,

    #[serde(default, with = "serde_optional_address")]
    pub continuation: &'a Option<ton_block::MsgAddressInt>,

    #[serde(with = "serde_uint256")]
    pub code_hash: &'a ton_types::UInt256,
}

#[derive(Serialize)]
pub struct SendMessage<'a> {
    #[serde(with = "serde_ton_block")]
    pub message: &'a ton_block::Message,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactions<'a> {
    pub limit: u64,

    #[serde(default, with = "serde_optional_string")]
    pub last_transaction_lt: Option<u64>,

    #[serde(with = "serde_address")]
    pub account: &'a ton_block::MsgAddressInt,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetTransaction<'a> {
    #[serde(with = "serde_uint256")]
    pub id: &'a ton_types::UInt256,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetDstTransaction<'a> {
    #[serde(with = "serde_uint256")]
    pub message_hash: &'a ton_types::UInt256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBlockResponse {
    #[serde(with = "serde_ton_block")]
    pub block: ton_block::Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockchainConfigResponse {
    pub global_id: i32,
    #[serde(default)]
    pub seqno: u32,
    #[serde(with = "serde_ton_block")]
    pub config: ton_block::ConfigParams,
}
