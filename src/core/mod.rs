pub mod accounts_storage;
pub mod contract_subscription;
pub mod generic_contract;
pub mod keystore;
pub mod models;
pub mod owners_cache;
pub mod token_wallet;
pub mod ton_wallet;
pub mod utils;

use anyhow::Result;

pub use self::contract_subscription::ContractSubscription;
use self::models::PollingMethod;
use crate::transport::Transport;

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

#[derive(Clone, Debug)]
pub struct InternalMessage {
    pub source: Option<ton_block::MsgAddressInt>,
    pub destination: ton_block::MsgAddressInt,
    pub amount: u64,
    pub bounce: bool,
    pub body: ton_types::SliceData,
}
