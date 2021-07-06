use std::borrow::Cow;
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
use crate::transport::models::{ExistingContract, RawContractState, RawTransaction};
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
    cached_custodians: Option<Vec<UInt256>>,
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
            cached_custodians: None,
        })
    }

    pub async fn subscribe_by_address(
        transport: Arc<dyn Transport>,
        address: MsgAddressInt,
        handler: Arc<dyn TonWalletSubscriptionHandler>,
    ) -> Result<Self> {
        let (public_key, contract_type) = match transport.get_contract_state(&address).await? {
            RawContractState::Exists(contract) => extract_wallet_init_data(&contract)?,
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
            cached_custodians: None,
        })
    }

    pub async fn subscribe_by_existing(
        transport: Arc<dyn Transport>,
        existing_wallet: ExistingWalletInfo,
        handler: Arc<dyn TonWalletSubscriptionHandler>,
    ) -> Result<Self> {
        let contract_subscription = ContractSubscription::subscribe_by_existing(
            transport.clone(),
            existing_wallet.address,
            existing_wallet.contract_state,
            make_transactions_handler(&handler),
        )
        .await?;

        Ok(Self {
            transport,
            public_key: existing_wallet.public_key,
            contract_type: existing_wallet.contract_type,
            contract_subscription,
            handler,
            cached_custodians: None,
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
        &mut self,
        current_state: &ton_block::AccountStuff,
        public_key: &PublicKey,
        destination: MsgAddressInt,
        amount: u64,
        bounce: bool,
        body: Option<SliceData>,
        expiration: Expiration,
    ) -> Result<TransferAction> {
        match self.contract_type {
            ContractType::Multisig(multisig_type) => {
                match &current_state.storage.state {
                    ton_block::AccountState::AccountFrozen(_) => {
                        return Err(TonWalletError::AccountIsFrozen.into())
                    }
                    ton_block::AccountState::AccountUninit => {
                        return Ok(TransferAction::DeployFirst)
                    }
                    ton_block::AccountState::AccountActive(_) => {}
                };
                self.update_cached_custodians(Cow::Borrowed(current_state), multisig_type)?;

                let has_multiple_owners = match &self.cached_custodians {
                    Some(custodians) => custodians.len() > 1,
                    None => return Err(TonWalletError::CustodiansNotFound.into()),
                };

                multisig::prepare_transfer(
                    public_key,
                    has_multiple_owners,
                    self.address().clone(),
                    destination,
                    amount,
                    bounce,
                    body,
                    expiration,
                )
            }
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

    pub fn prepare_confirm_transaction(
        &self,
        current_state: &ton_block::AccountStuff,
        public_key: &PublicKey,
        transaction_id: u64,
        expiration: Expiration,
    ) -> Result<Box<dyn UnsignedMessage>> {
        match self.contract_type {
            ContractType::Multisig(multisig_type) => {
                let gen_timings = self.contract_state().gen_timings;
                let last_transaction_id = &self
                    .contract_state()
                    .last_transaction_id
                    .ok_or(TonWalletError::LastTransactionNotFound)?;

                let has_pending_transaction = multisig::find_pending_transaction(
                    multisig_type,
                    Cow::Borrowed(current_state),
                    gen_timings,
                    last_transaction_id,
                    transaction_id,
                )?;
                if !has_pending_transaction {
                    return Err(TonWalletError::PendingTransactionNotFound.into());
                }

                multisig::prepare_confirm_transaction(
                    public_key,
                    self.address().clone(),
                    transaction_id,
                    expiration,
                )
            }
            ContractType::WalletV3 => Err(TonWalletError::PendingTransactionNotFound.into()),
        }
    }

    pub async fn fetch_custodians(&mut self) -> Result<Vec<UInt256>> {
        if self.cached_custodians == None {
            match self.contract_type {
                ContractType::Multisig(multisig_type) => {
                    let account_stuff = self.get_contract_state().await?;
                    self.update_cached_custodians(Cow::Owned(account_stuff), multisig_type)?;
                }
                ContractType::WalletV3 => {
                    self.cached_custodians = Some(vec![self.public_key.to_bytes().into()]);
                }
            }
        }

        match self.cached_custodians.clone() {
            Some(custodians) => Ok(custodians),
            None => Err(TonWalletError::CustodiansNotFound.into()),
        }
    }

    pub async fn fetch_unconfirmed_transactions(
        &mut self,
    ) -> Result<Vec<MultisigPendingTransaction>> {
        match self.contract_type {
            ContractType::Multisig(multisig_type) => {
                let account_stuff = self.get_contract_state().await?;
                let gen_timings = self.contract_state().gen_timings;
                let last_transaction_id = &self
                    .contract_state()
                    .last_transaction_id
                    .ok_or(TonWalletError::LastTransactionNotFound)?;

                self.update_cached_custodians(Cow::Borrowed(&account_stuff), multisig_type)?;
                let custodians = self
                    .cached_custodians
                    .as_ref()
                    .ok_or(TonWalletError::CustodiansNotFound)?;

                Ok(multisig::get_pending_transaction(
                    multisig_type,
                    Cow::Owned(account_stuff),
                    gen_timings,
                    last_transaction_id,
                    custodians,
                )?)
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

    fn update_cached_custodians(
        &mut self,
        account_stuff: Cow<'_, ton_block::AccountStuff>,
        multisig_type: multisig::MultisigType,
    ) -> Result<()> {
        if self.cached_custodians.is_some() {
            return Ok(());
        }

        let gen_timings = self.contract_state().gen_timings;
        let last_transaction_id = &self
            .contract_state()
            .last_transaction_id
            .ok_or(TonWalletError::LastTransactionNotFound)?;

        self.cached_custodians = Some(multisig::get_custodians(
            multisig_type,
            account_stuff,
            gen_timings,
            last_transaction_id,
        )?);

        Ok(())
    }

    async fn get_contract_state(&self) -> Result<ton_block::AccountStuff> {
        match self
            .transport
            .get_contract_state(self.contract_subscription.address())
            .await?
        {
            RawContractState::Exists(state) => Ok(state.account),
            RawContractState::NotExists => Err(TonWalletError::AccountNotExists.into()),
        }
    }
}

pub fn extract_wallet_init_data(contract: &ExistingContract) -> Result<(PublicKey, ContractType)> {
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
        Ok((public_key, ContractType::Multisig(multisig_type)))
    } else if wallet_v3::is_wallet_v3(&code_hash) {
        let public_key =
            PublicKey::from_bytes(wallet_v3::InitData::try_from(data)?.public_key()).trust_me();
        Ok((public_key, ContractType::WalletV3))
    } else {
        Err(TonWalletError::InvalidContractType.into())
    }
}

const WALLET_TYPES_BY_POPULARITY: [ContractType; 5] = [
    ContractType::Multisig(MultisigType::SurfWallet),
    ContractType::WalletV3,
    ContractType::Multisig(MultisigType::SafeMultisigWallet),
    ContractType::Multisig(MultisigType::SetcodeMultisigWallet),
    ContractType::Multisig(MultisigType::SafeMultisigWallet24h),
];

pub async fn find_existing_wallets(
    transport: &dyn Transport,
    public_key: &PublicKey,
    workchain_id: i8,
) -> Result<Vec<ExistingWalletInfo>> {
    use futures::stream::{FuturesUnordered, TryStreamExt};

    WALLET_TYPES_BY_POPULARITY
        .iter()
        .map(|&contract_type| async move {
            let address = compute_address(public_key, contract_type, workchain_id);

            let contract_state = transport.get_contract_state(&address).await?;

            Ok(ExistingWalletInfo {
                address,
                public_key: *public_key,
                contract_type,
                contract_state: contract_state.brief(),
            })
        })
        .collect::<FuturesUnordered<_>>()
        .try_collect::<Vec<ExistingWalletInfo>>()
        .await
}

pub struct ExistingWalletInfo {
    pub address: MsgAddressInt,
    pub public_key: PublicKey,
    pub contract_type: ContractType,
    pub contract_state: ContractState,
}

pub trait InternalMessageSender {
    fn prepare_transfer(
        &mut self,
        current_state: &ton_block::AccountStuff,
        public_key: &PublicKey,
        message: InternalMessage,
        expiration: Expiration,
    ) -> Result<TransferAction>;
}

impl InternalMessageSender for TonWallet {
    fn prepare_transfer(
        &mut self,
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
    #[error("Account is frozen")]
    AccountIsFrozen,
    #[error("Invalid contract type")]
    InvalidContractType,
    #[error("Last transaction not found")]
    LastTransactionNotFound,
    #[error("Custodians not found")]
    CustodiansNotFound,
    #[error("Pending transactino not found")]
    PendingTransactionNotFound,
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
