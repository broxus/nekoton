use anyhow::Result;
use async_trait::async_trait;
use ton_block::MsgAddressInt;

use crate::core::models::TransactionId;

use self::models::*;

pub mod adnl;
pub mod gql;
pub mod models;

#[async_trait]
pub trait Transport: Send + Sync {
    fn max_transactions_per_fetch(&self) -> u8;

    async fn get_blockchain_config(&self) -> Result<ton_executor::BlockchainConfig>;
    async fn send_message(&self, message: &ton_block::Message) -> Result<()>;
    async fn get_account_state(&self, address: &MsgAddressInt) -> Result<ContractState>;
    async fn get_transactions(
        &self,
        address: MsgAddressInt,
        from: TransactionId,
        count: u8,
    ) -> Result<Vec<TransactionFull>>;
}
