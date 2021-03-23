pub mod models;
pub mod wallet;

use std::convert::TryFrom;

use anyhow::Result;
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
