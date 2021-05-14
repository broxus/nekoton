use anyhow::Result;
use async_trait::async_trait;
use ton_block::MsgAddressInt;

use crate::core::models::TransactionId;

use self::models::*;

pub mod adnl;
pub mod gql;
pub mod jrpc_transport;
pub mod models;
mod utils;

#[async_trait]
pub trait Transport: Send + Sync {
    fn max_transactions_per_fetch(&self) -> u8;

    async fn send_message(&self, message: &ton_block::Message) -> Result<()>;

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState>;

    async fn get_transactions(
        &self,
        address: MsgAddressInt,
        from: TransactionId,
        count: u8,
    ) -> Result<Vec<RawTransaction>>;

    async fn get_latest_key_block(&self) -> Result<ton_block::Block>;

    async fn get_blockchain_config(&self) -> Result<ton_executor::BlockchainConfig>;
}
