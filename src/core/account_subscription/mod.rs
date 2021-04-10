use std::sync::Arc;

use anyhow::Result;
use futures::StreamExt;
use ton_block::MsgAddressInt;

use super::models::{AccountState, PendingTransaction, TransactionId, TransactionsBatchInfo};
use super::{utils, PollingMethod};
use crate::core::utils::PendingTransactionsExt;
use crate::helpers::abi::Executor;
use crate::transport::models::{ContractState, TransactionFull};
use crate::transport::Transport;

#[derive(Clone)]
pub struct AccountSubscription {
    transport: Arc<dyn Transport>,
    address: MsgAddressInt,
    account_state: AccountState,
    latest_known_transaction: Option<TransactionId>,
    pending_transactions: Vec<PendingTransaction>,
}

impl AccountSubscription {
    pub async fn subscribe<FC, FT>(
        transport: Arc<dyn Transport>,
        address: MsgAddressInt,
        on_contract_state: FC,
        on_transactions_found: FT,
    ) -> Result<Self>
    where
        FC: FnMut(&ContractState),
        FT: FnMut(Vec<TransactionFull>, TransactionsBatchInfo),
    {
        let mut result = Self {
            transport,
            address,
            account_state: Default::default(),
            latest_known_transaction: None,
            pending_transactions: Vec::new(),
        };

        if result.refresh_contract_state(on_contract_state).await? {
            let count = result.transport.max_transactions_per_fetch();
            result
                .refresh_latest_transactions(
                    count,
                    Some(count as usize),
                    on_transactions_found,
                    |_, _| {},
                )
                .await?;
        }

        Ok(result)
    }

    pub fn address(&self) -> &MsgAddressInt {
        &self.address
    }

    pub fn account_state(&self) -> &AccountState {
        &self.account_state
    }

    pub fn pending_transactions(&self) -> &[PendingTransaction] {
        &self.pending_transactions
    }

    pub fn polling_method(&self) -> PollingMethod {
        if self.pending_transactions.is_empty() {
            PollingMethod::Manual
        } else {
            PollingMethod::Reliable
        }
    }

    pub fn add_pending_transaction(&mut self, pending_transaction: PendingTransaction) {
        self.pending_transactions.push(pending_transaction);
    }

    pub async fn send(
        &mut self,
        message: &ton_block::Message,
        expire_at: u32,
    ) -> Result<PendingTransaction> {
        let pending_transaction =
            self.pending_transactions
                .add_message(&self.address, message, expire_at)?;
        match self.transport.send_message(message).await {
            // return pending transaction on success
            Ok(()) => Ok(pending_transaction),
            // remove pending transaction from queue on error
            Err(e) => {
                self.pending_transactions.cancel(&pending_transaction);
                Err(e)
            }
        }
    }

    pub async fn refresh<FC, FT, FM, FE>(
        &mut self,
        on_contract_state: FC,
        on_transactions_found: FT,
        on_message_sent: FM,
        mut on_message_expired: FE,
    ) -> Result<()>
    where
        FC: FnMut(&ContractState),
        FT: FnMut(Vec<TransactionFull>, TransactionsBatchInfo),
        FM: FnMut(PendingTransaction, TransactionFull),
        FE: FnMut(PendingTransaction),
    {
        // optimistic prediction, that there were at most N new transactions
        const INITIAL_TRANSACTION_COUNT: u8 = 4;

        if self.refresh_contract_state(on_contract_state).await? {
            let count = u8::min(
                self.transport.max_transactions_per_fetch(),
                INITIAL_TRANSACTION_COUNT,
            );

            // get all new transactions until known id
            self.refresh_latest_transactions(count, None, on_transactions_found, on_message_sent)
                .await?;
        }

        if !self.pending_transactions.is_empty() {
            let current_utime = self.account_state.gen_timings.current_utime();
            self.check_expired_transactions(current_utime, &mut on_message_expired);
        }

        Ok(())
    }

    pub async fn handle_block<FT, FM, FE>(
        &mut self,
        block: &ton_block::Block,
        mut on_transactions_found: FT,
        mut on_message_sent: FM,
        mut on_message_expired: FE,
    ) -> Result<Option<AccountState>>
    where
        FT: FnMut(Vec<TransactionFull>, TransactionsBatchInfo),
        FM: FnMut(PendingTransaction, TransactionFull),
        FE: FnMut(PendingTransaction),
    {
        let block = utils::parse_block(&self.address, &self.account_state, block)?;

        let mut new_account_state = None;
        if let Some((account_state, new_transactions)) = block.data {
            new_account_state = Some(account_state);

            if let Some((mut new_transactions, batch_info)) = new_transactions {
                new_transactions.reverse();
                self.check_executed_transactions(&new_transactions, &mut on_message_sent);

                if let Some(first) = new_transactions.first() {
                    self.latest_known_transaction = Some(first.id());
                    on_transactions_found(new_transactions, batch_info);
                }
            }
        }

        self.check_expired_transactions(block.current_utime, &mut on_message_expired);

        Ok(new_account_state)
    }

    pub async fn estimate_fees(&mut self, message: &ton_block::Message) -> Result<u64> {
        let blockchain_config = self.transport.get_blockchain_config().await?;
        let state = match self.transport.get_contract_state(&self.address).await? {
            ContractState::Exists(state) => state,
            _ => return Err(ContractExecutionError::ContractNotFound.into()),
        };

        let transaction = Executor::new(
            blockchain_config,
            state.account,
            state.timings,
            &state.last_transaction_id,
        )
        .disable_signature_check()
        .run(message)?;

        Ok(transaction.total_fees.grams.0 as u64)
    }

    pub async fn refresh_contract_state<FC>(&mut self, mut on_contract_state: FC) -> Result<bool>
    where
        FC: FnMut(&ContractState),
    {
        let contract_state = self.transport.get_contract_state(&self.address).await?;
        let new_account_state = contract_state.account_state();

        Ok(if new_account_state != self.account_state {
            on_contract_state(&contract_state);
            self.account_state = new_account_state;
            true
        } else {
            false
        })
    }

    /// # Arguments
    ///
    /// * `initial_count` - optimistic prediction, that there were at most N new transactions
    /// * `limit` - max transaction count to be requested
    pub async fn refresh_latest_transactions<FT, FM>(
        &mut self,
        initial_count: u8,
        limit: Option<usize>,
        mut on_transactions_found: FT,
        mut on_message_sent: FM,
    ) -> Result<()>
    where
        FT: FnMut(Vec<TransactionFull>, TransactionsBatchInfo),
        FM: FnMut(PendingTransaction, TransactionFull),
    {
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
            if new_transactions.is_empty() {
                continue;
            }

            // requires `&mut self`, so `request_transactions` must use outer objects
            self.check_executed_transactions(&new_transactions, &mut on_message_sent);

            if new_latest_known_transaction.is_none() {
                new_latest_known_transaction =
                    new_transactions.first().map(|transaction| transaction.id());
            }

            on_transactions_found(new_transactions, batch_info);
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
    pub async fn preload_transactions<FT>(
        &mut self,
        from: TransactionId,
        mut on_transactions_found: FT,
    ) -> Result<()>
    where
        FT: FnMut(Vec<TransactionFull>, TransactionsBatchInfo),
    {
        let transactions = self
            .transport
            .get_transactions(
                self.address.clone(),
                from,
                self.transport.max_transactions_per_fetch(),
            )
            .await?;

        if let (Some(first), Some(last)) = (transactions.first(), transactions.last()) {
            let batch_info = TransactionsBatchInfo {
                min_lt: last.data.lt, // transactions in response are in descending order
                max_lt: first.data.lt,
                old: true,
            };

            on_transactions_found(transactions, batch_info);
        }

        Ok(())
    }

    /// Searches executed pending transactions and notifies the handler if some were found
    fn check_executed_transactions<FM>(
        &mut self,
        transactions: &[TransactionFull],
        on_message_sent: &mut FM,
    ) where
        FM: FnMut(PendingTransaction, TransactionFull),
    {
        self.pending_transactions.retain(|pending| {
            let transaction = match transactions
                .iter()
                .find(|transaction| pending.eq(*transaction))
            {
                Some(transaction) => transaction,
                None => return true,
            };

            on_message_sent(pending.clone(), transaction.clone());
            false
        });
    }

    /// Removes expired transactions and notifies the handler with them
    fn check_expired_transactions<FE>(&mut self, current_utime: u32, on_message_expired: &mut FE)
    where
        FE: FnMut(PendingTransaction),
    {
        self.pending_transactions.retain(|pending| {
            let expired = current_utime > pending.expire_at;
            if expired {
                on_message_expired(pending.clone());
            }
            !expired
        })
    }
}

#[derive(thiserror::Error, Debug)]
enum ContractExecutionError {
    #[error("Contract not found")]
    ContractNotFound,
}
