use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use ton_block::{GetRepresentationHash, MsgAddressInt};

use nekoton_utils::Clock;

use super::models::{ContractState, PendingTransaction, Transaction, TransactionsBatchInfo};
use super::{ContractSubscription, PollingMethod, TransactionExecutionOptions};
use crate::core::utils;
use crate::transport::models::{RawContractState, RawTransaction};
use crate::transport::Transport;

pub struct GenericContract {
    contract_subscription: ContractSubscription,
    handler: Arc<dyn GenericContractSubscriptionHandler>,
}

impl GenericContract {
    pub async fn subscribe(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        address: MsgAddressInt,
        handler: Arc<dyn GenericContractSubscriptionHandler>,
        preload_transactions: bool,
    ) -> Result<Self> {
        let contract_subscription = {
            let handler = handler.as_ref();

            #[allow(trivial_casts)]
            ContractSubscription::subscribe(
                clock,
                transport,
                address,
                &mut make_contract_state_handler(handler),
                preload_transactions
                    .then(|| make_transactions_handler(handler))
                    .as_mut()
                    .map(|x| x as _),
            )
            .await?
        };

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
        let handler = self.handler.as_ref();
        self.contract_subscription
            .refresh(
                &mut make_contract_state_handler(handler),
                &mut make_transactions_handler(handler),
                &mut make_message_sent_handler(handler),
                &mut make_message_expired_handler(handler),
            )
            .await?;

        Ok(())
    }

    pub async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()> {
        let handler = self.handler.as_ref();
        let new_account_state = self.contract_subscription.handle_block(
            block,
            &mut make_transactions_handler(handler),
            &mut make_message_sent_handler(handler),
            &mut make_message_expired_handler(handler),
        )?;

        if let Some(account_state) = new_account_state {
            handler.on_state_changed(account_state);
        }

        Ok(())
    }

    pub async fn preload_transactions(&mut self, from_lt: u64) -> Result<()> {
        let handler = self.handler.as_ref();
        self.contract_subscription
            .preload_transactions(from_lt, &mut make_transactions_handler(handler))
            .await
    }

    pub async fn estimate_fees(&mut self, message: &ton_block::Message) -> Result<u128> {
        self.contract_subscription.estimate_fees(message).await
    }

    pub async fn execute_transaction_locally(
        &mut self,
        message: &ton_block::Message,
        options: TransactionExecutionOptions,
    ) -> Result<Transaction> {
        let transaction = self
            .contract_subscription
            .execute_transaction_locally(message, options)
            .await?;
        let hash = transaction.hash()?;

        Transaction::try_from((hash, transaction)).map_err(From::from)
    }
}

fn make_contract_state_handler(
    handler: &dyn GenericContractSubscriptionHandler,
) -> impl FnMut(&RawContractState) + '_ {
    move |contract_state| handler.on_state_changed(contract_state.brief())
}

fn make_transactions_handler(
    handler: &dyn GenericContractSubscriptionHandler,
) -> impl FnMut(Vec<RawTransaction>, TransactionsBatchInfo) + '_ {
    move |transactions, batch_info| {
        let transactions = utils::convert_transactions(transactions).collect();
        handler.on_transactions_found(transactions, batch_info)
    }
}

fn make_message_sent_handler(
    handler: &dyn GenericContractSubscriptionHandler,
) -> impl FnMut(PendingTransaction, RawTransaction) + '_ {
    move |pending_transaction, transaction| {
        let transaction = Transaction::try_from((transaction.hash, transaction.data)).ok();
        handler.on_message_sent(pending_transaction, transaction);
    }
}

fn make_message_expired_handler(
    handler: &'_ dyn GenericContractSubscriptionHandler,
) -> impl FnMut(PendingTransaction) + '_ {
    move |pending_transaction| handler.on_message_expired(pending_transaction)
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
