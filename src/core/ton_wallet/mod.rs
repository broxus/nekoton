use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use serde::{Deserialize, Serialize};
use ton_block::MsgAddressInt;
use ton_types::{SliceData, UInt256};

use crate::core::{utils, InternalMessage};
use crate::crypto::UnsignedMessage;
use crate::helpers;
use crate::transport::models::{RawContractState, RawTransaction};
use crate::transport::Transport;
use crate::utils::*;

use super::models::{
    ContractState, Expiration, MultisigPendingTransaction, PendingTransaction, Transaction,
    TransactionAdditionalInfo, TransactionId, TransactionWithData, TransactionsBatchInfo,
};
use super::{ContractSubscription, PollingMethod};

pub use self::multisig::MultisigType;

mod multisig;
mod wallet_v3;

pub const DEFAULT_WORKCHAIN: i8 = 0;

#[derive(Clone)]
pub struct TonWallet {
    transport: Arc<dyn Transport>,
    public_key: PublicKey,
    contract_type: ContractType,
    contract_subscription: ContractSubscription,
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

        let contract_subscription = ContractSubscription::subscribe(
            transport.clone(),
            address,
            make_contract_state_handler(&handler),
            make_transactions_handler(&handler),
        )
        .await?;

        Ok(Self {
            transport,
            public_key,
            contract_type,
            contract_subscription,
            handler,
        })
    }

    pub async fn subscribe_by_address(
        transport: Arc<dyn Transport>,
        address: MsgAddressInt,
        handler: Arc<dyn TonWalletSubscriptionHandler>,
    ) -> Result<Self> {
        let (public_key, contract_type) = match transport.get_contract_state(&address).await? {
            RawContractState::Exists(contract) => {
                let (code, data) = match &contract.account.storage.state {
                    ton_block::AccountState::AccountActive(ton_block::StateInit {
                        code: Some(code),
                        data: Some(data),
                        ..
                    }) => (code, data),
                    _ => return Err(TonWalletError::AccountNotExists.into()),
                };

                let code_hash = code.repr_hash();
                if let Some(multisig_type) = multisig::guess_multisig_type(&code_hash) {
                    let public_key = helpers::abi::extract_public_key(&contract.account)?;
                    (public_key, ContractType::Multisig(multisig_type))
                } else if wallet_v3::is_wallet_v3(&code_hash) {
                    let public_key =
                        PublicKey::from_bytes(wallet_v3::InitData::try_from(data)?.public_key())
                            .trust_me();
                    (public_key, ContractType::WalletV3)
                } else {
                    return Err(TonWalletError::InvalidContractType.into());
                }
            }
            RawContractState::NotExists => return Err(TonWalletError::AccountNotExists.into()),
        };

        let contract_subscription = ContractSubscription::subscribe(
            transport.clone(),
            address,
            make_contract_state_handler(&handler),
            make_transactions_handler(&handler),
        )
        .await?;

        Ok(Self {
            transport,
            public_key,
            contract_type,
            contract_subscription,
            handler,
        })
    }

    pub fn address(&self) -> &MsgAddressInt {
        self.contract_subscription.address()
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn contract_type(&self) -> ContractType {
        self.contract_type
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

    pub fn details(&self) -> TonWalletDetails {
        self.contract_type.details()
    }

    pub fn prepare_deploy(&self, expiration: Expiration) -> Result<Box<dyn UnsignedMessage>> {
        match self.contract_type {
            ContractType::WalletV3 => wallet_v3::prepare_deploy(&self.public_key, expiration),
            ContractType::Multisig(multisig_type) => multisig::prepare_deploy(
                &self.public_key,
                multisig_type,
                expiration,
                &[self.public_key],
                1,
            ),
        }
    }

    pub fn prepare_deploy_with_multiple_owners(
        &self,
        expiration: Expiration,
        custodians: &[PublicKey],
        req_confirms: u8,
    ) -> Result<Box<dyn UnsignedMessage>> {
        match self.contract_type {
            ContractType::Multisig(multisig_type) => multisig::prepare_deploy(
                &self.public_key,
                multisig_type,
                expiration,
                custodians,
                req_confirms,
            ),
            ContractType::WalletV3 => Err(TonWalletError::InvalidContractType.into()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_transfer(
        &self,
        current_state: &ton_block::AccountStuff,
        public_key: &PublicKey,
        destination: MsgAddressInt,
        amount: u64,
        bounce: bool,
        body: Option<SliceData>,
        expiration: Expiration,
    ) -> Result<TransferAction> {
        match self.contract_type {
            ContractType::Multisig(_) => multisig::prepare_transfer(
                public_key,
                current_state,
                destination,
                amount,
                bounce,
                body,
                expiration,
            ),
            ContractType::WalletV3 => wallet_v3::prepare_transfer(
                public_key,
                current_state,
                destination,
                amount,
                bounce,
                body,
                expiration,
            ),
        }
    }

    pub async fn get_custodians(&self) -> Result<Vec<UInt256>> {
        match self.contract_type {
            ContractType::Multisig(multisig_type) => {
                let account_stuff = self.get_contract_state().await?;
                let gen_timings = self.contract_state().gen_timings;
                let last_transaction_id = &self
                    .contract_state()
                    .last_transaction_id
                    .ok_or(TonWalletError::LastTransactionNotFound)?;

                multisig::run_local(
                    multisig_type,
                    "getCustodians",
                    account_stuff,
                    gen_timings,
                    last_transaction_id,
                )
                .and_then(multisig::parse_multisig_contract_custodians)
            }
            ContractType::WalletV3 => Ok(vec![self.public_key.to_bytes().into()]),
        }
    }

    pub async fn get_pending_transactions(&self) -> Result<Vec<MultisigPendingTransaction>> {
        match self.contract_type {
            ContractType::Multisig(multisig_type) => {
                let account_stuff = self.get_contract_state().await?;
                let gen_timings = self.contract_state().gen_timings;
                let last_transaction_id = &self
                    .contract_state()
                    .last_transaction_id
                    .ok_or(TonWalletError::LastTransactionNotFound)?;

                let custodians = multisig::run_local(
                    multisig_type,
                    "getCustodians",
                    account_stuff.clone(),
                    gen_timings,
                    last_transaction_id,
                )
                .and_then(multisig::parse_multisig_contract_custodians)?;

                let transactions = multisig::run_local(
                    multisig_type,
                    "getTransactions",
                    account_stuff,
                    gen_timings,
                    last_transaction_id,
                )
                .and_then(|tokens| {
                    multisig::parse_multisig_contract_pending_transactions(tokens, &custodians)
                })?;

                Ok(transactions)
            }
            ContractType::WalletV3 => Ok(Vec::new()),
        }
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

    async fn get_contract_state(&self) -> Result<ton_block::AccountStuff> {
        match self
            .transport
            .get_contract_state(self.contract_subscription.address())
            .await?
        {
            RawContractState::Exists(state) => Ok(state.account),
            RawContractState::NotExists => Err(TonWalletError::ContractNotFound.into()),
        }
    }
}

pub trait InternalMessageSender {
    fn prepare_transfer(
        &self,
        current_state: &ton_block::AccountStuff,
        public_key: &PublicKey,
        message: InternalMessage,
        expiration: Expiration,
    ) -> Result<TransferAction>;
}

impl InternalMessageSender for TonWallet {
    fn prepare_transfer(
        &self,
        current_state: &ton_block::AccountStuff,
        public_key: &PublicKey,
        message: InternalMessage,
        expiration: Expiration,
    ) -> Result<TransferAction> {
        if matches!(message.source, Some(source) if &source != self.address()) {
            return Err(InternalMessageSenderError::InvalidSender.into());
        }

        self.prepare_transfer(
            current_state,
            public_key,
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

#[derive(thiserror::Error, Debug)]
enum TonWalletError {
    #[error("Account not exists")]
    AccountNotExists,
    #[error("Invalid contract type")]
    InvalidContractType,
    #[error("Contract not found")]
    ContractNotFound,
    #[error("Last transaction not found")]
    LastTransactionNotFound,
}

fn make_contract_state_handler<T>(handler: &'_ T) -> impl FnMut(&RawContractState) + '_
where
    T: AsRef<dyn TonWalletSubscriptionHandler>,
{
    move |contract_state| handler.as_ref().on_state_changed(contract_state.brief())
}

fn make_transactions_handler<T>(
    handler: &'_ T,
) -> impl FnMut(Vec<RawTransaction>, TransactionsBatchInfo) + '_
where
    T: AsRef<dyn TonWalletSubscriptionHandler>,
{
    move |transactions, batch_info| {
        let transactions = utils::convert_transactions_with_data(
            transactions,
            utils::parse_transaction_additional_info,
        )
        .collect();
        handler
            .as_ref()
            .on_transactions_found(transactions, batch_info)
    }
}

fn make_message_sent_handler<T>(
    handler: &'_ T,
) -> impl FnMut(PendingTransaction, RawTransaction) + '_
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
    #[serde(with = "serde_u64")]
    pub min_amount: u64,
    pub supports_payload: bool,
    pub supports_multiple_owners: bool,
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
    fn fmt(&self, f: &'_ mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    fn on_state_changed(&self, new_state: ContractState);

    /// Called every time new transactions are detected.
    /// - When new block found
    /// - When manually requesting the latest transactions (can be called several times)
    /// - When preloading transactions
    fn on_transactions_found(
        &self,
        transactions: Vec<TransactionWithData<TransactionAdditionalInfo>>,
        batch_info: TransactionsBatchInfo,
    );
}
