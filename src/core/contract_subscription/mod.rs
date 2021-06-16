use std::sync::Arc;

use anyhow::Result;
use futures::StreamExt;
use ton_block::MsgAddressInt;

use super::models::{
    ContractState, GenTimings, PendingTransaction, TransactionId, TransactionsBatchInfo,
};
use super::{utils, PollingMethod};
use crate::core::utils::PendingTransactionsExt;
use crate::helpers::abi::Executor;
use crate::transport::models::{RawContractState, RawTransaction};
use crate::transport::Transport;

/// Used as a base object for different listeners implementation
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct ContractSubscription {
    transport: Arc<dyn Transport>,
    address: MsgAddressInt,
    contract_state: ContractState,
    latest_known_transaction: Option<TransactionId>,
    pending_transactions: Vec<PendingTransaction>,
    initialized: bool,
}

impl ContractSubscription {
    pub async fn subscribe<FC, FT>(
        transport: Arc<dyn Transport>,
        address: MsgAddressInt,
        on_contract_state: FC,
        on_transactions_found: FT,
    ) -> Result<Self>
    where
        FC: FnMut(&RawContractState),
        FT: FnMut(Vec<RawTransaction>, TransactionsBatchInfo),
    {
        let mut result = Self {
            transport,
            address,
            contract_state: Default::default(),
            latest_known_transaction: None,
            pending_transactions: Vec::new(),
            initialized: false,
        };

        if result.refresh_contract_state(on_contract_state).await? {
            let count = result.transport.info().max_transactions_per_fetch;
            result
                .refresh_latest_transactions(
                    count,
                    Some(count as usize),
                    on_transactions_found,
                    |_, _| {},
                )
                .await?;
        }

        result.initialized = true;

        Ok(result)
    }

    pub fn address(&self) -> &MsgAddressInt {
        &self.address
    }

    pub fn contract_state(&self) -> &ContractState {
        &self.contract_state
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
        FC: FnMut(&RawContractState),
        FT: FnMut(Vec<RawTransaction>, TransactionsBatchInfo),
        FM: FnMut(PendingTransaction, RawTransaction),
        FE: FnMut(PendingTransaction),
    {
        // optimistic prediction, that there were at most N new transactions
        const INITIAL_TRANSACTION_COUNT: u8 = 4;

        if self.refresh_contract_state(on_contract_state).await? {
            let count = u8::min(
                self.transport.info().max_transactions_per_fetch,
                INITIAL_TRANSACTION_COUNT,
            );

            // get all new transactions until known id
            self.refresh_latest_transactions(count, None, on_transactions_found, on_message_sent)
                .await?;
        }

        if !self.pending_transactions.is_empty() {
            let current_utime = self.contract_state.gen_timings.current_utime();
            self.check_expired_transactions(current_utime, &mut on_message_expired);
        }

        Ok(())
    }

    pub fn handle_block<FT, FM, FE>(
        &mut self,
        block: &ton_block::Block,
        mut on_transactions_found: FT,
        mut on_message_sent: FM,
        mut on_message_expired: FE,
    ) -> Result<Option<ContractState>>
    where
        FT: FnMut(Vec<RawTransaction>, TransactionsBatchInfo),
        FM: FnMut(PendingTransaction, RawTransaction),
        FE: FnMut(PendingTransaction),
    {
        let block = utils::parse_block(&self.address, &self.contract_state, block)?;

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
            RawContractState::Exists(state) => state,
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
        FC: FnMut(&RawContractState),
    {
        let contract_state = self.transport.get_contract_state(&self.address).await?;
        let new_contract_state = contract_state.brief();

        if new_contract_state == self.contract_state {
            return Ok(false);
        }

        match (
            new_contract_state.gen_timings,
            self.contract_state.gen_timings,
        ) {
            // Do nothing if we received a state with the old logical time
            (
                GenTimings::Known {
                    gen_lt: new_gen_lt, ..
                },
                GenTimings::Known {
                    gen_lt: old_gen_lt, ..
                },
            ) if new_gen_lt <= old_gen_lt => Ok(false),
            // Notify otherwise
            _ => {
                on_contract_state(&contract_state);
                self.contract_state = new_contract_state;
                Ok(true)
            }
        }
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
        FT: FnMut(Vec<RawTransaction>, TransactionsBatchInfo),
        FM: FnMut(PendingTransaction, RawTransaction),
    {
        let from = match self.contract_state.last_transaction_id {
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

        let mut new_transactions = Vec::new();
        while let Some(transactions) = transactions.next().await {
            new_transactions.extend(transactions.into_iter());
        }

        let batch_info = match (new_transactions.first(), new_transactions.last()) {
            (Some(first), Some(last)) => Some(TransactionsBatchInfo {
                min_lt: last.data.lt, // transactions in response are in descending order
                max_lt: first.data.lt,
                old: false,
            }),
            _ => None,
        };

        if let Some(mut batch_info) = batch_info {
            // requires `&mut self`, so `request_transactions` must use outer objects
            self.check_executed_transactions(&new_transactions, &mut on_message_sent);

            if new_latest_known_transaction.is_none() {
                new_latest_known_transaction =
                    new_transactions.first().map(|transaction| transaction.id());
            }

            // `utils::request_transactions` returns new transactions. So, to mark
            // first transactions we get as old, we should use initialization flag.
            batch_info.old = !self.initialized;

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
        FT: FnMut(Vec<RawTransaction>, TransactionsBatchInfo),
    {
        let transactions = self
            .transport
            .get_transactions(
                self.address.clone(),
                from,
                self.transport.info().max_transactions_per_fetch,
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
        transactions: &[RawTransaction],
        on_message_sent: &mut FM,
    ) where
        FM: FnMut(PendingTransaction, RawTransaction),
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
