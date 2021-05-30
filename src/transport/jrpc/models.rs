use serde::{Deserialize, Serialize};

use crate::core::models::TransactionId;
use crate::utils::*;

#[derive(Serialize, Clone)]
pub struct GetContractState<'a> {
    #[serde(with = "serde_address")]
    pub address: &'a ton_block::MsgAddressInt,
}

#[derive(Serialize, Clone)]
pub struct SendMessage<'a> {
    #[serde(with = "serde_message")]
    pub message: &'a ton_block::Message,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactions<'a> {
    #[serde(with = "serde_address")]
    pub address: &'a ton_block::MsgAddressInt,
    pub transaction_id: TransactionId,
    pub count: u8,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RawTransactionsList {
    #[serde(with = "serde_bytes_base64")]
    pub transactions: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawBlock {
    #[serde(with = "serde_ton_block")]
    pub block: ton_block::Block,
}
