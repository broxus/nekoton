use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ton_executor::BlockchainConfig;

pub enum Abi {
    Contract(AbiContract),
    Json(String),
    Handle(AbiHandle),

    Serialized(AbiContract),
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AbiHandle(u32);

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AbiContract {
    pub obsolete_abi_version: u32,
    pub abi_version: u32,
    #[serde(default)]
    pub header: Vec<String>,
    #[serde(default)]
    pub functions: Vec<AbiFunction>,
    #[serde(default)]
    pub events: Vec<AbiEvent>,
    #[serde(default)]
    pub data: Vec<AbiData>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AbiData {
    pub key: u64,
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
    #[serde(default)]
    pub components: Vec<AbiParam>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AbiEvent {
    pub name: String,
    pub inputs: Vec<AbiParam>,
    #[serde(default)]
    pub id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AbiParam {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
    #[serde(default)]
    pub components: Vec<AbiParam>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AbiFunction {
    pub name: String,
    pub inputs: Vec<AbiParam>,
    pub outputs: Vec<AbiParam>,
    #[serde(default)]
    pub id: Option<String>,
}

pub(crate) struct ResolvedExecutionOptions {
    pub blockchain_config: Arc<BlockchainConfig>,
    pub block_time: u32,
    pub block_lt: u64,
    pub transaction_lt: u64,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ExecutionOptions {
    /// boc with config
    pub blockchain_config: Option<String>,
    /// time that is used as transaction time
    pub block_time: Option<u32>,
    /// block logical time
    pub block_lt: Option<u64>,
    /// transaction logical time
    pub transaction_lt: Option<u64>,
}
