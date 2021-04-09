pub mod models;
mod multisig;
pub mod transactions;
mod wallet_v3;

use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use ed25519_dalek::PublicKey;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use ton_block::MsgAddressInt;
use ton_types::SliceData;

pub use self::multisig::MultisigType;
use super::models::{
    AccountState, AccountSubscriptionError, Expiration, GenTimings, PendingTransaction,
    Transaction, TransactionId, TransactionsBatchInfo,
};
use super::{utils, PollingMethod};
use crate::core::utils::PendingTransactionsExt;
use crate::crypto::UnsignedMessage;
use crate::helpers::abi::Executor;
use crate::transport::models::{ContractState, TransactionFull};
use crate::transport::Transport;

pub const DEFAULT_WORKCHAIN: i8 = 0;

pub struct TonWallet {
    public_key: PublicKey,
    contract_type: ContractType,
}

impl TonWallet {
    pub fn new(public_key: PublicKey, contract_type: ContractType) -> Self {
        Self {
            public_key,
            contract_type,
        }
    }

    pub fn compute_address(&self) -> MsgAddressInt {
        compute_address(&self.public_key, self.contract_type, DEFAULT_WORKCHAIN)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn contract_type(&self) -> ContractType {
        self.contract_type
    }

    pub fn prepare_deploy(&self, expiration: Expiration) -> Result<Box<dyn UnsignedMessage>> {
        match self.contract_type {
            ContractType::Multisig(multisig_type) => {
                multisig::prepare_deploy(&self.public_key, multisig_type, expiration)
            }
            ContractType::WalletV3 => wallet_v3::prepare_deploy(&self.public_key, expiration),
        }
    }

    pub fn prepare_transfer(
        &self,
        current_state: &ton_block::AccountStuff,
        destination: MsgAddressInt,
        amount: u64,
        bounce: bool,
        body: Option<SliceData>,
        expiration: Expiration,
    ) -> Result<TransferAction> {
        match self.contract_type {
            ContractType::Multisig(_) => multisig::prepare_transfer(
                &self.public_key,
                current_state,
                destination,
                amount,
                bounce,
                body,
                expiration,
            ),
            ContractType::WalletV3 => wallet_v3::prepare_transfer(
                &self.public_key,
                current_state,
                destination,
                amount,
                bounce,
                body,
                expiration,
            ),
        }
    }
}

#[derive(Clone)]
pub enum TransferAction {
    DeployFirst,
    Sign(Box<dyn UnsignedMessage>),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContractType {
    Multisig(MultisigType),
    WalletV3,
}

impl FromStr for ContractType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "WalletV3" => Self::WalletV3,
            s => Self::Multisig(MultisigType::from_str(s)?),
        })
    }
}

impl std::fmt::Display for ContractType {
    fn fmt(&self, f: &'_ mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::WalletV3 => f.write_str("WalletV3"),
            Self::Multisig(multisig_type) => multisig_type.fmt(f),
        }
    }
}

pub fn compute_address(
    public_key: &PublicKey,
    contract_type: ContractType,
    workchain_id: i8,
) -> MsgAddressInt {
    match contract_type {
        ContractType::Multisig(multisig_type) => {
            multisig::compute_contract_address(public_key, multisig_type, workchain_id)
        }
        ContractType::WalletV3 => wallet_v3::compute_contract_address(public_key, workchain_id),
    }
}

#[derive(Clone)]
pub struct AccountSubscription {
    transport: Arc<dyn Transport>,
    address: MsgAddressInt,
    contract_state: ContractState,
    latest_known_transaction: Option<TransactionId>,
    pending_transactions: Vec<PendingTransaction>,
}

impl AccountSubscription {
    pub fn address(&self) -> &MsgAddressInt {
        &self.address
    }

    pub fn contract_state(&self) -> &ContractState {
        &self.contract_state
    }

    pub fn pending_transactions(&self) -> &[PendingTransaction] {
        &self.pending_transactions
    }

    pub async fn subscribe(transport: Arc<dyn Transport>, address: MsgAddressInt) -> Result<Self> {
        let mut result = Self {
            transport,
            address,
            contract_state: ContractState::NotExists,
            latest_known_transaction: None,
            pending_transactions: Vec::new(),
        };
        result.refresh_contract_state().await?;

        // {
        //     let count = result.transport.max_transactions_per_fetch();
        //     result
        //         .refresh_latest_transactions(count, Some(count as usize))
        //         .await?;
        // }

        Ok(result)
    }

    pub async fn estimate_fees(&mut self, message: &ton_block::Message) -> Result<u64> {
        let blockchain_config = self.transport.get_blockchain_config().await?;
        let state = match self.transport.get_account_state(&self.address).await? {
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

    pub async fn refresh_contract_state(&mut self) -> Result<bool> {
        let new_state = self.transport.get_account_state(&self.address).await?;

        Ok(if new_state != self.contract_state {
            self.contract_state = new_state;
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
        let from = match &self.contract_state {
            ContractState::Exists(state) => state.last_transaction_id.to_transaction_id(),
            ContractState::NotExists => return Ok(()),
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
    fn check_executed_transactions<F>(
        &mut self,
        transactions: &[TransactionFull],
        on_message_sent: &mut F,
    ) where
        F: FnMut(PendingTransaction, TransactionFull),
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
    fn check_expired_transactions<FE>(&mut self, current_utime: u32, mut on_message_expired: FE)
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

    async fn send(
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

    pub async fn refresh<FT, FM, FE>(
        &mut self,
        mut on_transactions_found: FT,
        mut on_message_sent: FM,
        mut on_message_expired: FE,
    ) -> Result<()>
    where
        FT: FnMut(Vec<TransactionFull>, TransactionsBatchInfo),
        FM: FnMut(PendingTransaction, TransactionFull),
        FE: FnMut(PendingTransaction),
    {
        // optimistic prediction, that there were at most N new transactions
        const INITIAL_TRANSACTION_COUNT: u8 = 4;

        if self.refresh_contract_state().await? {
            let count = u8::min(
                self.transport.max_transactions_per_fetch(),
                INITIAL_TRANSACTION_COUNT,
            );

            // get all new transactions until known id
            self.refresh_latest_transactions(count, None, on_transactions_found, on_message_sent)
                .await?;
        }

        if !self.pending_transactions.is_empty() {
            if let ContractState::Exists(state) = &self.contract_state {
                let current_utime = state.timings.current_utime();
                self.check_expired_transactions(current_utime, on_message_expired);
            }
        }

        Ok(())
    }

    async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()> {
        let block = utils::parse_block(&self.address, &self.contract_state, block)?;

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

pub trait TonWalletSubscriptionHandler: Send + Sync {
    /// Called when found transaction which is relative with one of the pending transactions
    fn on_message_sent(&self, pending_transaction: PendingTransaction, transaction: Transaction);

    /// Called when no transactions produced for the specific message before some expiration time
    fn on_message_expired(&self, pending_transaction: PendingTransaction);

    /// Called every time a new state is detected
    fn on_state_changed(&self, new_state: AccountState);

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
