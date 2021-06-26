use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use ton_block::MsgAddressInt;

use super::models::{
    ContractState, PendingTransaction, Transaction, TransactionId, TransactionsBatchInfo,
};
use super::{ContractSubscription, PollingMethod};
use crate::core::utils;
use crate::transport::models::{RawContractState, RawTransaction};
use crate::transport::Transport;

#[derive(Clone)]
pub struct GenericContract {
    contract_subscription: ContractSubscription,
    handler: Arc<dyn GenericContractSubscriptionHandler>,
}

impl GenericContract {
    pub async fn subscribe(
        transport: Arc<dyn Transport>,
        address: MsgAddressInt,
        handler: Arc<dyn GenericContractSubscriptionHandler>,
    ) -> Result<Self> {
        let contract_subscription = ContractSubscription::subscribe(
            transport,
            address,
            make_contract_state_handler(&handler),
            make_transactions_handler(&handler),
        )
        .await?;

        Ok(Self {
            contract_subscription,
            handler,
        })
    }

    pub fn address(&self) -> &MsgAddressInt {
        self.contract_subscription.address()
    }

    pub fn contract_state(&self) -> &ContractState {
        self.contract_subscription.contract_state()
    }

    pub fn pending_transactions(&self) -> &[PendingTransaction] {
        self.contract_subscription.pending_transactions()
    }

    pub fn polling_method(&self) -> PollingMethod {
        self.contract_subscription.polling_method()
    }

    pub async fn send(
        &mut self,
        message: &ton_block::Message,
        expire_at: u32,
    ) -> Result<PendingTransaction> {
        self.contract_subscription.send(message, expire_at).await
    }

    pub async fn refresh(&mut self) -> Result<()> {
        self.contract_subscription
            .refresh(
                make_contract_state_handler(&self.handler),
                make_transactions_handler(&self.handler),
                make_message_sent_handler(&self.handler),
                make_message_expired_handler(&self.handler),
            )
            .await?;

        Ok(())
    }

    pub async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()> {
        let new_account_state = self.contract_subscription.handle_block(
            block,
            make_transactions_handler(&self.handler),
            make_message_sent_handler(&self.handler),
            make_message_expired_handler(&self.handler),
        )?;

        if let Some(account_state) = new_account_state {
            self.handler.on_state_changed(account_state);
        }

        Ok(())
    }

    pub async fn preload_transactions(&mut self, from: TransactionId) -> Result<()> {
        self.contract_subscription
            .preload_transactions(from, make_transactions_handler(&self.handler))
            .await
    }

    pub async fn estimate_fees(&mut self, message: &ton_block::Message) -> Result<u64> {
        self.contract_subscription.estimate_fees(message).await
    }
}

fn make_contract_state_handler<T>(handler: &'_ T) -> impl FnMut(&RawContractState) + '_
where
    T: AsRef<dyn GenericContractSubscriptionHandler>,
{
    move |contract_state| handler.as_ref().on_state_changed(contract_state.brief())
}

fn make_transactions_handler<T>(
    handler: &'_ T,
) -> impl FnMut(Vec<RawTransaction>, TransactionsBatchInfo) + '_
where
    T: AsRef<dyn GenericContractSubscriptionHandler>,
{
    move |transactions, batch_info| {
        let transactions = utils::convert_transactions(transactions).collect();
        handler
            .as_ref()
            .on_transactions_found(transactions, batch_info)
    }
}

fn make_message_sent_handler<T>(
    handler: &'_ T,
) -> impl FnMut(PendingTransaction, RawTransaction) + '_
where
    T: AsRef<dyn GenericContractSubscriptionHandler>,
{
    move |pending_transaction, transaction| {
        let transaction = Transaction::try_from((transaction.hash, transaction.data)).ok();
        handler
            .as_ref()
            .on_message_sent(pending_transaction, transaction);
    }
}

fn make_message_expired_handler<T>(handler: &'_ T) -> impl FnMut(PendingTransaction) + '_
where
    T: AsRef<dyn GenericContractSubscriptionHandler>,
{
    move |pending_transaction| handler.as_ref().on_message_expired(pending_transaction)
}

pub trait GenericContractSubscriptionHandler: Send + Sync {
    /// Called when found transaction which is relative with one of the pending transactions
    fn on_message_sent(
        &self,
        pending_transaction: PendingTransaction,
        transaction: Option<Transaction>,
    );

    /// Called when no transactions produced for the specific message before some expiration time
    fn on_message_expired(&self, pending_transaction: PendingTransaction);

    /// Called every time a new state is detected
    fn on_state_changed(&self, new_state: ContractState);

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
