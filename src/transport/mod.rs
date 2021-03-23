use anyhow::Result;
use async_trait::async_trait;
use ton_block::MsgAddressInt;

pub mod adnl;
pub mod gql;
pub mod models;

use self::models::*;
use crate::core::models::TransactionId;

#[async_trait]
pub trait Transport: Send + Sync {
    async fn send_message(&self, message: &ton_block::Message) -> Result<()>;
    async fn get_account_state(&self, address: &MsgAddressInt) -> Result<ContractState>;
    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from: &TransactionId,
        count: u8,
    ) -> Result<Vec<TransactionFull>>;
}
