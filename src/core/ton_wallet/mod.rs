mod multisig;
mod wallet_v3;

use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use serde::{Deserialize, Serialize};
use ton_block::MsgAddressInt;
use ton_types::SliceData;

pub use self::multisig::MultisigType;
use super::models::{
    AccountState, Expiration, PendingTransaction, Transaction, TransactionId, TransactionsBatchInfo,
};
use super::{AccountSubscription, PollingMethod};
use crate::core::{utils, InternalMessage};
use crate::crypto::UnsignedMessage;
use crate::transport::models::{ContractState, TransactionFull};
use crate::transport::Transport;

pub const DEFAULT_WORKCHAIN: i8 = 0;

#[derive(Clone)]
pub struct TonWallet {
    public_key: PublicKey,
    contract_type: ContractType,
    account_subscription: AccountSubscription,
    handler: Arc<dyn TonWalletSubscriptionHandler>,
}

impl TonWallet {
    pub async fn subscribe(
        transport: Arc<dyn Transport>,
        public_key: PublicKey,
        contract_type: ContractType,
        handler: Arc<dyn TonWalletSubscriptionHandler>,
    ) -> Result<Self> {
        let address = compute_address(&public_key, contract_type, DEFAULT_WORKCHAIN);

        let account_subscription = AccountSubscription::subscribe(
            transport,
            address,
            make_contract_state_handler(&handler),
            make_transactions_handler(&handler),
        )
        .await?;

        Ok(Self {
            public_key,
            contract_type,
            account_subscription,
            handler,
        })
    }

    pub fn address(&self) -> &MsgAddressInt {
        &self.account_subscription.address()
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn contract_type(&self) -> ContractType {
        self.contract_type
    }

    pub fn account_state(&self) -> &AccountState {
        &self.account_subscription.account_state()
    }

    pub fn pending_transactions(&self) -> &[PendingTransaction] {
        &self.account_subscription.pending_transactions()
    }

    pub fn polling_method(&self) -> PollingMethod {
        self.account_subscription.polling_method()
    }

    pub fn details(&self) -> TonWalletDetails {
        self.contract_type.details()
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

    pub async fn send(
        &mut self,
        message: &ton_block::Message,
        expire_at: u32,
    ) -> Result<PendingTransaction> {
        self.account_subscription.send(message, expire_at).await
    }

    pub async fn refresh(&mut self) -> Result<()> {
        self.account_subscription
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
        let new_account_state = self.account_subscription.handle_block(
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
        self.account_subscription
            .preload_transactions(from, make_transactions_handler(&self.handler))
            .await
    }

    pub async fn estimate_fees(&mut self, message: &ton_block::Message) -> Result<u64> {
        self.account_subscription.estimate_fees(message).await
    }
}

pub trait InternalMessageSender {
    fn prepare_transfer(
        &self,
        current_state: &ton_block::AccountStuff,
        message: InternalMessage,
        expiration: Expiration,
    ) -> Result<TransferAction>;
}

impl InternalMessageSender for TonWallet {
    fn prepare_transfer(
        &self,
        current_state: &ton_block::AccountStuff,
        message: InternalMessage,
        expiration: Expiration,
    ) -> Result<TransferAction> {
        if matches!(message.source, Some(source) if &source != self.address()) {
            return Err(InternalMessageSenderError::InvalidSender.into());
        }

        self.prepare_transfer(
            current_state,
            message.destination,
            message.amount,
            message.bounce,
            Some(message.body),
            expiration,
        )
    }
}

#[derive(thiserror::Error, Debug)]
enum InternalMessageSenderError {
    #[error("Invalid sender")]
    InvalidSender,
}

fn make_contract_state_handler<T>(handler: &'_ T) -> impl FnMut(&ContractState) + '_
where
    T: AsRef<dyn TonWalletSubscriptionHandler>,
{
    move |contract_state| {
        handler
            .as_ref()
            .on_state_changed(contract_state.account_state())
    }
}

fn make_transactions_handler<T>(
    handler: &'_ T,
) -> impl FnMut(Vec<TransactionFull>, TransactionsBatchInfo) + '_
where
    T: AsRef<dyn TonWalletSubscriptionHandler>,
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
) -> impl FnMut(PendingTransaction, TransactionFull) + '_
where
    T: AsRef<dyn TonWalletSubscriptionHandler>,
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
    T: AsRef<dyn TonWalletSubscriptionHandler>,
{
    move |pending_transaction| handler.as_ref().on_message_expired(pending_transaction)
}

#[derive(Clone)]
pub enum TransferAction {
    DeployFirst,
    Sign(Box<dyn UnsignedMessage>),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TonWalletDetails {
    pub requires_separate_deploy: bool,
    pub min_amount: u64,
    pub supports_payload: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContractType {
    Multisig(MultisigType),
    WalletV3,
}

impl ContractType {
    pub fn details(&self) -> TonWalletDetails {
        match self {
            ContractType::Multisig(_) => multisig::DETAILS,
            ContractType::WalletV3 => wallet_v3::DETAILS,
        }
    }
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

pub trait TonWalletSubscriptionHandler: Send + Sync {
    /// Called when found transaction which is relative with one of the pending transactions
    fn on_message_sent(
        &self,
        pending_transaction: PendingTransaction,
        transaction: Option<Transaction>,
    );

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
