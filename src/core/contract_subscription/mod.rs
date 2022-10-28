use std::sync::Arc;

use anyhow::Result;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use ton_block::MsgAddressInt;

use nekoton_abi::{Executor, LastTransactionId};
use nekoton_utils::*;

use super::models::{
    ContractState, PendingTransaction, ReliableBehavior, TransactionsBatchInfo,
    TransactionsBatchType,
};
use super::{utils, PollingMethod};
use crate::core::utils::{MessageContext, PendingTransactionsExt};
use crate::transport::models::{RawContractState, RawTransaction};
use crate::transport::Transport;

/// Used as a base object for different listeners implementation
pub struct ContractSubscription {
    clock: Arc<dyn Clock>,
    transport: Arc<dyn Transport>,
    address: MsgAddressInt,
    contract_state: ContractState,
    latest_known_lt: Option<u64>,
    pending_transactions: Vec<PendingTransaction>,
    transactions_synced: bool,
}

impl ContractSubscription {
    pub async fn subscribe(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        address: MsgAddressInt,
        on_contract_state: OnContractState<'_>,
        on_transactions_found: Option<OnTransactionsFound<'_>>,
    ) -> Result<Self> {
        let mut result = Self {
            clock,
            transport,
            address,
            contract_state: Default::default(),
            latest_known_lt: None,
            pending_transactions: Vec::new(),
            transactions_synced: false,
        };

        result.transactions_synced = !result.refresh_contract_state(on_contract_state).await?;
        if !result.transactions_synced {
            if let Some(on_transactions_found) = on_transactions_found {
                // Preload transactions if `on_transactions_found` specified
                let count = result.transport.info().max_transactions_per_fetch;
                result
                    .refresh_latest_transactions(
                        count,
                        Some(count as usize),
                        TransactionsBatchType::Old,
                        on_transactions_found,
                        &mut |_, _| {},
                    )
                    .await?;
            } else {
                // Otherwise assume that all transactions are already loaded
                result.latest_known_lt =
                    result.contract_state.last_transaction_id.map(|id| id.lt());
                result.transactions_synced = true;
            }
        }

        Ok(result)
    }

    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
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
            // Relaxed polling when there are no pending transactions
            PollingMethod::Manual
        } else if self.transactions_synced {
            // All transports could use reliable polling if there are some
            // pending transactions and all recent transactions were received
            PollingMethod::Reliable
        } else {
            match self.transport.info().reliable_behavior {
                // Nothing changed for polling, it will just request
                // transactions one more time during refresh
                ReliableBehavior::IntensivePolling => PollingMethod::Reliable,

                // Special case for transport which supports block walking
                // and not all recent transactions were received.
                //
                // It is needed to receive all these transactions first,
                // otherwise there will be gaps.
                ReliableBehavior::BlockWalking => PollingMethod::Manual,
            }
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
        let ctx = MessageContext {
            latest_lt: self
                .contract_state
                .last_transaction_id
                .map(|id| id.lt())
                .unwrap_or_default(),
            created_at: self.clock.now_sec_u64() as u32,
            expire_at,
        };
        let pending_transaction =
            self.pending_transactions
                .add_message(&self.address, message, ctx)?;

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

    pub async fn refresh(
        &mut self,
        on_contract_state: OnContractState<'_>,
        on_transactions_found: OnTransactionsFound<'_>,
        on_message_sent: OnMessageSent<'_>,
        on_message_expired: OnMessageExpired<'_>,
    ) -> Result<()> {
        // optimistic prediction, that there were at most N new transactions
        const INITIAL_TRANSACTION_COUNT: u8 = 4;

        // NOTE: refresh transactions every time state changes, or there are
        // new transactions, which we still need to receive (e.g. state has new
        // last_transaction_id, but the last known transaction is not equal to id)
        if self.refresh_contract_state(on_contract_state).await? || !self.transactions_synced {
            let count = u8::min(
                self.transport.info().max_transactions_per_fetch,
                INITIAL_TRANSACTION_COUNT,
            );

            // get all new transactions until known id
            self.refresh_latest_transactions(
                count,
                None,
                TransactionsBatchType::New,
                on_transactions_found,
                on_message_sent,
            )
            .await?;
        }

        // Only check expired messages when we can guarantee, that
        // all transactions until current state were received
        if !self.pending_transactions.is_empty() && self.transactions_synced {
            let current_utime = self
                .contract_state
                .gen_timings
                .current_utime(self.clock.as_ref());
            self.check_expired_transactions(current_utime, on_message_expired);
        }

        Ok(())
    }

    pub fn handle_block(
        &mut self,
        block: &ton_block::Block,
        on_transactions_found: OnTransactionsFound<'_>,
        on_message_sent: OnMessageSent<'_>,
        on_message_expired: OnMessageExpired<'_>,
    ) -> Result<Option<ContractState>> {
        let block = utils::parse_block(&self.address, &self.contract_state, block)?;

        let mut new_account_state = None;
        if let Some((account_state, new_transactions)) = block.data {
            new_account_state = Some(account_state);

            if let Some((mut new_transactions, batch_info)) = new_transactions {
                new_transactions.reverse();
                self.check_executed_transactions(&new_transactions, on_message_sent);

                if let Some(first) = new_transactions.first() {
                    self.latest_known_lt = Some(first.data.lt);
                    on_transactions_found(new_transactions, batch_info);
                }
            }
        }

        self.check_expired_transactions(block.current_utime, on_message_expired);

        Ok(new_account_state)
    }

    pub async fn estimate_fees(&self, message: &ton_block::Message) -> Result<u128> {
        let transaction = self
            .execute_transaction_locally(
                message,
                TransactionExecutionOptions {
                    disable_signature_check: true,
                    ..Default::default()
                },
            )
            .await?;

        Ok(
            if let ton_block::TransactionDescr::Ordinary(descr) = transaction.read_description()? {
                compute_total_transaction_fees(&transaction, &descr)
            } else {
                transaction.total_fees.grams.0
            },
        )
    }

    pub async fn execute_transaction_locally(
        &self,
        message: &ton_block::Message,
        options: TransactionExecutionOptions,
    ) -> Result<ton_block::Transaction> {
        let blockchain_config = self
            .transport
            .get_blockchain_config(self.clock.as_ref())
            .await?;
        let mut account = match self.transport.get_contract_state(&self.address).await? {
            RawContractState::Exists(state) => ton_block::Account::Account(state.account),
            RawContractState::NotExists => ton_block::Account::AccountNone,
        };

        if let Some(balance) = options.override_balance {
            account.set_balance(balance.into());
        }

        let mut executor = Executor::new(self.clock.as_ref(), blockchain_config, account)?;
        if options.disable_signature_check {
            executor.disable_signature_check();
        }

        executor.run_once(message)
    }

    /// Updates contract state. Returns whether the state was changed
    ///
    /// NOTE: resets `transactions_synced` if state changes
    pub async fn refresh_contract_state(
        &mut self,
        on_contract_state: OnContractState<'_>,
    ) -> Result<bool> {
        let contract_state = self.transport.get_contract_state(&self.address).await?;
        let new_contract_state = contract_state.brief();

        match new_contract_state.last_lt.cmp(&self.contract_state.last_lt) {
            // Notify with new state
            std::cmp::Ordering::Greater => {
                on_contract_state(&contract_state);
                self.contract_state = new_contract_state;
                self.transactions_synced = false;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// # Arguments
    ///
    /// * `initial_count` - optimistic prediction, that there were at most N new transactions
    /// * `limit` - max transaction count to be requested
    pub async fn refresh_latest_transactions(
        &mut self,
        initial_count: u8,
        limit: Option<usize>,
        batch_type: TransactionsBatchType,
        on_transactions_found: OnTransactionsFound<'_>,
        on_message_sent: OnMessageSent<'_>,
    ) -> Result<()> {
        let last_tx_id_from_state = match self.contract_state.last_transaction_id {
            Some(id) => id,
            None => return Ok(()),
        };
        let from_lt = last_tx_id_from_state.lt();

        let mut new_latest_known_transaction = None;

        // clone request context, because `&mut self` is needed later
        let mut transactions = utils::request_transactions(
            self.transport.as_ref(),
            &self.address,
            from_lt,
            self.latest_known_lt,
            initial_count,
            limit,
        );

        let mut new_transactions = Vec::<RawTransaction>::new();
        while let Some(transactions) = transactions.next().await {
            new_transactions.extend(transactions?.into_iter());
        }
        drop(transactions);

        if let (Some(first), Some(last)) = (new_transactions.first(), new_transactions.last()) {
            // Transactions in response are in descending order
            let max_lt = first.data.lt;
            let min_lt = last.data.lt;

            self.transactions_synced = match &last_tx_id_from_state {
                // In case we know the exact lt of the last transaction,
                // transactions are synced when max_lt is equal to it
                LastTransactionId::Exact(id_from_state) => id_from_state.lt <= max_lt,
                // In case we know only last_trans_lt from AccountStorage,
                // we should compute the same last_trans_lt using message count
                LastTransactionId::Inexact { latest_lt } => {
                    *latest_lt <= max_lt + 1 + first.data.outmsg_cnt as u64
                }
            };

            // requires `&mut self`, so `request_transactions` must use outer objects
            self.check_executed_transactions(&new_transactions, on_message_sent);

            if new_latest_known_transaction.is_none() {
                new_latest_known_transaction = Some(max_lt);
            }

            on_transactions_found(
                new_transactions,
                TransactionsBatchInfo {
                    min_lt,
                    max_lt,
                    batch_type,
                },
            );
        };

        if let Some(id) = new_latest_known_transaction {
            self.latest_known_lt = Some(id);
        }

        Ok(())
    }

    /// Loads older transactions since specified id and notifies the handler with them
    ///
    /// **NOTE: returns transactions, sorted by lt in descending order**
    pub async fn preload_transactions(
        &mut self,
        from_lt: u64,
        on_transactions_found: OnTransactionsFound<'_>,
    ) -> Result<()> {
        let transactions = self
            .transport
            .get_transactions(
                &self.address,
                from_lt,
                self.transport.info().max_transactions_per_fetch,
            )
            .await?;

        if let (Some(first), Some(last)) = (transactions.first(), transactions.last()) {
            let batch_info = TransactionsBatchInfo {
                min_lt: last.data.lt, // transactions in response are in descending order
                max_lt: first.data.lt,
                batch_type: TransactionsBatchType::Old,
            };

            on_transactions_found(transactions, batch_info);
        }

        Ok(())
    }

    /// Searches executed pending transactions and notifies the handler if some were found
    fn check_executed_transactions(
        &mut self,
        transactions: &[RawTransaction],
        on_message_sent: OnMessageSent<'_>,
    ) {
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
    fn check_expired_transactions(
        &mut self,
        current_utime: u32,
        on_message_expired: OnMessageExpired<'_>,
    ) {
        self.pending_transactions.retain(|pending| {
            let expired = current_utime > pending.expire_at;
            if expired {
                on_message_expired(pending.clone());
            }
            !expired
        })
    }
}

type OnContractState<'a> = &'a mut (dyn FnMut(&RawContractState) + Send + Sync);
type OnTransactionsFound<'a> =
    &'a mut (dyn FnMut(Vec<RawTransaction>, TransactionsBatchInfo) + Send + Sync);
type OnMessageSent<'a> = &'a mut (dyn FnMut(PendingTransaction, RawTransaction) + Send + Sync);
type OnMessageExpired<'a> = &'a mut (dyn FnMut(PendingTransaction) + Send + Sync);

#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionExecutionOptions {
    pub disable_signature_check: bool,
    pub override_balance: Option<u64>,
}
