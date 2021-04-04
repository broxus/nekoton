pub mod models;
pub mod ton_wallet;
mod utils;

use anyhow::Result;
use async_trait::async_trait;

use self::models::{
    AccountState, PendingTransaction, PollingMethod, Transaction, TransactionsBatchInfo,
};
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

pub trait AccountSubscriptionHandler: Send + Sync {
    /// Called when found transaction which is relative with one of the pending transactions
    fn on_message_sent(&self, pending_transaction: PendingTransaction, transaction: Transaction);

    /// Called when no transactions produced for the specific message before some expiration time
    fn on_message_expired(&self, pending_transaction: PendingTransaction);

    /// Called every time a new state is detected
    fn on_state_changed(&self, new_state: AccountState);

    /// Called every time new transactions are detected.
    /// - When new block found
    /// - When manually requesting the latest transactions (can be called several times)
    /// - When preloading transactions
    fn on_transactions_found(
        &self,
        transactions: Vec<Transaction>,
        batch_info: TransactionsBatchInfo,
    );
}

#[async_trait]
pub trait AccountSubscription {
    /// Send a message to subscribed account and ensure it is sent or expired
    async fn send(
        &mut self,
        message: &ton_block::Message,
        expire_at: u32,
    ) -> Result<PendingTransaction>;

    /// Called by manual polling
    async fn refresh(&mut self) -> Result<()>;

    /// Called by block-walking
    async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()>;

    /// Returns current polling method
    fn polling_method(&self) -> PollingMethod;
}
