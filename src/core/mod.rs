use anyhow::Result;
use nekoton_utils::*;
use serde::{Deserialize, Serialize};

pub use self::contract_subscription::{
    ContractSubscription, ContractSubscriptionCachedState, TransactionExecutionOptions,
};
use self::models::PollingMethod;
use crate::transport::Transport;

pub mod accounts_storage;
pub mod contract_subscription;
pub mod dens;
pub mod generic_contract;
pub mod keystore;
pub use super::models;
pub mod jetton_wallet;
pub mod nft_wallet;
pub mod owners_cache;
pub mod parsing;
pub mod token_wallet;
pub mod ton_wallet;
pub mod transactions_tree;
pub mod utils;

pub struct TonInterface {
    transport: Box<dyn Transport>,
}

impl TonInterface {
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self { transport }
    }

    pub async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        self.transport.send_message(message).await
    }

    pub fn set_transport(&mut self, transport: Box<dyn Transport>) {
        self.transport = transport;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InternalMessage {
    #[serde(
        with = "serde_optional_address",
        skip_serializing_if = "Option::is_none"
    )]
    pub source: Option<ton_block::MsgAddressInt>,
    #[serde(with = "serde_address")]
    pub destination: ton_block::MsgAddressInt,
    #[serde(with = "serde_string")]
    pub amount: u128,
    pub bounce: bool,
    #[serde(with = "serde_boc")]
    pub body: ton_types::SliceData,
}
