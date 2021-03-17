use anyhow::Result;
use async_trait::async_trait;
use ton_block::MsgAddressInt;

pub mod adnl;
pub mod models;

use self::models::*;

#[async_trait]
pub trait Transport: Send + Sync {
    async fn send_message(&self, data: &[u8]) -> Result<()>;
    async fn get_masterchain_info(&self) -> Result<LastBlockIdExt>;
    async fn get_account_state(
        &self,
        last_block_id: &LastBlockIdExt,
        address: &MsgAddressInt,
    ) -> Result<AccountState>;
    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from: &TransactionId,
        count: u8,
    ) -> Result<Vec<Transaction>>;
}
