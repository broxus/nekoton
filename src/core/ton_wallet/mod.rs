use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use ton_block::MsgAddressInt;

use super::{
    utils, AccountSubscription, AccountSubscriptionError, AccountSubscriptionHandler, PollingMethod,
};
use crate::core::models::{
    AccountState, GenTimings, PendingTransaction, Transaction, TransactionId, TransactionsBatchInfo,
};
use crate::helpers::abi::Executor;
use crate::transport::models::ContractState;
use crate::transport::Transport;

#[derive(Clone)]
pub struct TonWalletSubscription {
    transport: Arc<dyn Transport>,
    handler: Arc<dyn AccountSubscriptionHandler>,
    address: MsgAddressInt,
    account_state: AccountState,
    latest_known_transaction: Option<TransactionId>,
    pending_transactions: Vec<PendingTransaction>,
}

impl TonWalletSubscription {
    pub fn address(&self) -> &MsgAddressInt {
        &self.address
    }

    pub fn account_state(&self) -> &AccountState {
        &self.account_state
    }

    pub fn pending_transactions(&self) -> &[PendingTransaction] {
        &self.pending_transactions
    }

    pub async fn subscribe(
        transport: Arc<dyn Transport>,
        address: MsgAddressInt,
        handler: Arc<dyn AccountSubscriptionHandler>,
    ) -> Result<TonWalletSubscription> {
        let mut result = TonWalletSubscription {
            transport,
            handler,
            address,
            account_state: AccountState {
                balance: 0,
                gen_timings: GenTimings::Unknown,
                last_transaction_id: None,
                is_deployed: false,
            },
            latest_known_transaction: None,
            pending_transactions: Vec::new(),
        };

        if result.refresh_account_state().await? {
            let count = result.transport.max_transactions_per_fetch();
            result
                .refresh_latest_transactions(count, Some(count as usize))
                .await?;
        }

        Ok(result)
    }

    /// Calculate message execution fees
    pub async fn estimate_fees(&mut self, message: &ton_block::Message) -> Result<u64> {
        let blockchain_config = self.transport.get_blockchain_config().await?;
        let (account, timings, last_transaction_id) =
            match self.transport.get_account_state(&self.address).await? {
                ContractState::Exists {
                    account,
                    timings,
                    last_transaction_id,
                } => (account, timings, last_transaction_id),
                _ => return Err(ContractExecutionError::ContractNotFound.into()),
            };

        let transaction = Executor::new(blockchain_config, account, timings, &last_transaction_id)
            .disable_signature_check()
            .run(message)?;

        Ok(transaction.total_fees.grams.0 as u64)
    }

    /// Requests current account state and notifies the handler if it was changed
    pub async fn refresh_account_state(&mut self) -> Result<bool> {
        let new_state = match self.transport.get_account_state(&self.address).await? {
            ContractState::NotExists => AccountState {
                balance: 0,
                gen_timings: GenTimings::Unknown,
                last_transaction_id: None,
                is_deployed: false,
            },
            ContractState::Exists {
                account,
                timings,
                last_transaction_id,
            } => AccountState {
                balance: account.storage.balance.grams.0 as u64,
                gen_timings: timings,
                last_transaction_id: Some(last_transaction_id),
                is_deployed: matches!(
                    account.storage.state,
                    ton_block::AccountState::AccountActive(_)
                ),
            },
        };

        match (
            &self.account_state.last_transaction_id,
            &new_state.last_transaction_id,
        ) {
            (None, Some(_)) => self.account_state = new_state,
            (Some(current), Some(new)) if current < new => self.account_state = new_state,
            _ => return Ok(false),
        }

        self.handler.on_state_changed(self.account_state.clone());

        Ok(true)
    }

    /// Requests the latest transactions and notifies the handler if some were found
    ///
    /// # Arguments
    ///
    /// * `initial_count` - optimistic prediction, that there were at most N new transactions
    /// * `limit` - max transaction count to be requested
    pub async fn refresh_latest_transactions(
        &mut self,
        initial_count: u8,
        limit: Option<usize>,
    ) -> Result<()> {
        let from = match self.account_state.last_transaction_id {
            Some(id) => id.to_transaction_id(),
            None => return Ok(()),
        };

        let mut new_latest_known_transaction = None;

        // clone request context, because `&mut self` is needed later
        let transport = self.transport.clone();
        let address = self.address.clone();
        let latest_known_transaction = self.latest_known_transaction;

        let mut transactions = utils::request_transactions(
            transport.as_ref(),
            &address,
            from,
            latest_known_transaction.as_ref(),
            initial_count,
            limit,
        );

        while let Some((new_transactions, batch_info)) = transactions.next().await {
            let new_transactions =
                utils::convert_transactions(new_transactions).collect::<Vec<_>>();
            if new_transactions.is_empty() {
                continue;
            }

            // requires `&mut self`, so `request_transactions` must use outer objects
            self.check_executed_transactions(&new_transactions);

            if new_latest_known_transaction.is_none() {
                new_latest_known_transaction =
                    new_transactions.first().map(|transaction| transaction.id);
            }

            self.handler
                .on_transactions_found(new_transactions, batch_info);
        }

        std::mem::drop(transactions);

        if let Some(id) = new_latest_known_transaction {
            self.latest_known_transaction = Some(id);
        }

        Ok(())
    }

    /// Loads older transactions since specified id and notifies the handler with them
    ///
    /// **NOTE: returns transactions, sorted by lt in descending order**
    pub async fn preload_transactions(&mut self, from: TransactionId) -> Result<()> {
        let transactions = self
            .transport
            .get_transactions(
                self.address.clone(),
                from,
                self.transport.max_transactions_per_fetch(),
            )
            .await?
            .into_iter()
            .filter_map(|transaction| {
                Transaction::try_from((transaction.hash, transaction.data)).ok()
            })
            .collect::<Vec<_>>();

        if let (Some(first), Some(last)) = (transactions.first(), transactions.last()) {
            let batch_info = TransactionsBatchInfo {
                min_lt: last.id.lt, // transactions in response are in descending order
                max_lt: first.id.lt,
                old: true,
            };

            self.handler.on_transactions_found(transactions, batch_info);
        }

        Ok(())
    }

    /// Searches executed pending transactions and notifies the handler if some were found
    fn check_executed_transactions(&mut self, transactions: &[Transaction]) {
        let handler = &self.handler;

        self.pending_transactions.retain(|pending| {
            let transaction = match transactions
                .iter()
                .find(|transaction| pending.eq(*transaction))
            {
                Some(transaction) => transaction,
                None => return true,
            };

            handler.on_message_sent(pending.clone(), transaction.clone());
            false
        });
    }

    /// Removes expired transactions and notifies the handler with them
    fn check_expired_transactions(&mut self, current_utime: u32) {
        let handler = &self.handler;

        self.pending_transactions.retain(|pending| {
            let expired = current_utime > pending.expire_at;
            if expired {
                handler.on_message_expired(pending.clone());
            }
            !expired
        })
    }
}

#[async_trait]
impl AccountSubscription for TonWalletSubscription {
    async fn send(
        &mut self,
        message: &ton_block::Message,
        expire_at: u32,
    ) -> Result<PendingTransaction> {
        let src = match message.header() {
            ton_block::CommonMsgInfo::ExtInMsgInfo(header) => {
                if header.dst == self.address {
                    None
                } else {
                    return Err(AccountSubscriptionError::InvalidMessageDestination.into());
                }
            }
            _ => return Err(AccountSubscriptionError::InvalidMessageType.into()),
        };

        let body_hash = message
            .body()
            .map(|body| body.hash(ton_types::cell::MAX_LEVEL))
            .unwrap_or_default();

        let pending_transaction = PendingTransaction {
            src,
            body_hash,
            expire_at,
        };

        self.pending_transactions.push(pending_transaction.clone());
        match self.transport.send_message(message).await {
            // return pending transaction on success
            Ok(()) => Ok(pending_transaction),
            // remove pending transaction from queue on error
            Err(e) => {
                if let Some(i) = self
                    .pending_transactions
                    .iter()
                    .position(|item| item.eq(&pending_transaction))
                {
                    self.pending_transactions.remove(i);
                }
                Err(e)
            }
        }
    }

    async fn refresh(&mut self) -> Result<()> {
        // optimistic prediction, that there were at most N new transactions
        const INITIAL_TRANSACTION_COUNT: u8 = 4;

        if self.refresh_account_state().await? {
            let count = u8::min(
                self.transport.max_transactions_per_fetch(),
                INITIAL_TRANSACTION_COUNT,
            );

            // get all new transactions until known id
            self.refresh_latest_transactions(count, None).await?;
        }

        if !self.pending_transactions.is_empty() {
            let current_utime = self.account_state.gen_timings.current_utime();
            self.check_expired_transactions(current_utime);
        }

        Ok(())
    }

    async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()> {
        let block = utils::parse_block(&self.address, &self.account_state, block)?;

        if let Some((account_state, new_transactions)) = block.data {
            self.handler.on_state_changed(account_state);

            if let Some((new_transactions, batch_info)) = new_transactions {
                let new_transactions = utils::convert_transactions(new_transactions)
                    .rev()
                    .collect::<Vec<_>>();
                self.check_executed_transactions(&new_transactions);
                if !new_transactions.is_empty() {
                    self.handler
                        .on_transactions_found(new_transactions, batch_info);
                }
            }
        }

        self.check_expired_transactions(block.current_utime);

        Ok(())
    }

    fn polling_method(&self) -> PollingMethod {
        if self.pending_transactions.is_empty() {
            PollingMethod::Manual
        } else {
            PollingMethod::Reliable
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum ContractExecutionError {
    #[error("Contract not found")]
    ContractNotFound,
}
