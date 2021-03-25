pub mod models;
pub mod wallet;

use std::convert::TryFrom;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use ton_block::{Deserializable, MsgAddressInt, Serializable};
use ton_types::UInt256;

use crate::transport::models::*;
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

#[derive(Debug, Copy, Clone)]
pub enum PollingMethod {
    /// Manual polling once a minute or by a click.
    /// Used when there are no pending transactions
    Manual,
    /// Block-walking for GQL or fast refresh for ADNL.
    /// Used when there are some pending transactions
    Reliable,
}

#[async_trait]
pub trait AccountSubscription {
    /// Send a message to subscribed account and ensure it is sent or expired
    async fn send(&mut self, message: &ton_block::Message) -> Result<()>;

    /// Called by manual polling
    async fn refresh(&mut self);

    /// Called by block-walking
    async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()>;
}
