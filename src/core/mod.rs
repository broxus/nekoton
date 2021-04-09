pub mod account_subscription;
pub mod models;
pub mod token_wallet;
pub mod ton_wallet;
mod utils;

use anyhow::Result;

pub use self::account_subscription::AccountSubscription;
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
