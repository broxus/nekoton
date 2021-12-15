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
#[serde(untagged)]
pub enum GetContractStateResponseTimings {
    #[serde(rename_all = "lowercase")]
    Old {
        #[serde(with = "serde_string")]
        gen_lt: u64,
        gen_utime: u32,
    },
    #[serde(rename_all = "camelCase")]
    New {
        #[serde(with = "serde_string")]
        gen_lt: u64,
        gen_utime: u32,
    },
}

impl GetContractStateResponseTimings {
    pub fn gen_lt(&self) -> u64 {
        match self {
            Self::Old { gen_lt, .. } => *gen_lt,
            Self::New { gen_lt, .. } => *gen_lt,
        }
    }

    pub fn gen_utime(&self) -> u32 {
        match self {
            Self::Old { gen_utime, .. } => *gen_utime,
            Self::New { gen_utime, .. } => *gen_utime,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_gen_timings() {
        let timings = serde_json::from_str::<GetContractStateResponseTimings>(
            r#"{"gen_lt":"123","gen_utime":321}"#,
        )
        .unwrap();
        assert!(matches!(
            timings,
            GetContractStateResponseTimings::Old {
                gen_lt: 123,
                gen_utime: 321
            }
        ));

        let timings = serde_json::from_str::<GetContractStateResponseTimings>(
            r#"{"genLt":"123","genUtime":321}"#,
        )
        .unwrap();
        assert!(matches!(
            timings,
            GetContractStateResponseTimings::New {
                gen_lt: 123,
                gen_utime: 321
            }
        ));
    }
}
