use std::borrow::Cow;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use serde::{Deserialize, Serialize};
use ton_block::MsgAddressInt;
use ton_types::UInt256;

pub use self::multisig::MultisigType;
use super::models::{
    ContractState, MultisigPendingTransaction, PendingTransaction, Transaction,
    TransactionAdditionalInfo, TransactionId, TransactionWithData, TransactionsBatchInfo,
};
use super::{ContractSubscription, PollingMethod};
use crate::core::parsing::*;
use crate::helpers;
use crate::transport::models::{ExistingContract, RawContractState, RawTransaction};
use crate::transport::Transport;
use crate::utils::*;

mod multisig;
mod wallet_v3;

pub const DEFAULT_WORKCHAIN: i8 = 0;
#[cfg(feature = "wallet")]
mod wallet_integration;
#[cfg(feature = "wallet")]
pub use wallet_integration::*;

pub struct TonWallet {
    public_key: PublicKey,
    wallet_type: WalletType,
    contract_subscription: ContractSubscription,
    handler: Arc<dyn TonWalletSubscriptionHandler>,
    wallet_data: WalletData,
}

impl TonWallet {
    pub async fn subscribe(
        transport: Arc<dyn Transport>,
        public_key: PublicKey,
        wallet_type: WalletType,
        handler: Arc<dyn TonWalletSubscriptionHandler>,
    ) -> Result<Self> {
        let address = compute_address(&public_key, wallet_type, DEFAULT_WORKCHAIN);

        let mut wallet_data = WalletData::default();

        let contract_subscription = ContractSubscription::subscribe(
            transport,
            address,
            make_contract_state_handler(&handler, &public_key, wallet_type, &mut wallet_data),
            make_transactions_handler(&handler, wallet_type),
        )
        .await?;

        Ok(Self {
            public_key,
            wallet_type,
            contract_subscription,
            handler,
            wallet_data,
        })
    }

    pub async fn subscribe_by_address(
        transport: Arc<dyn Transport>,
        address: MsgAddressInt,
        handler: Arc<dyn TonWalletSubscriptionHandler>,
    ) -> Result<Self> {
        let (public_key, wallet_type) = match transport.get_contract_state(&address).await? {
            RawContractState::Exists(contract) => extract_wallet_init_data(&contract)?,
            RawContractState::NotExists => return Err(TonWalletError::AccountNotExists.into()),
        };

        let mut wallet_data = WalletData::default();

        let contract_subscription = ContractSubscription::subscribe(
            transport,
            address,
            make_contract_state_handler(&handler, &public_key, wallet_type, &mut wallet_data),
            make_transactions_handler(&handler, wallet_type),
        )
        .await?;

        Ok(Self {
            public_key,
            wallet_type,
            contract_subscription,
            handler,
            wallet_data,
        })
    }

    pub async fn subscribe_by_existing(
        transport: Arc<dyn Transport>,
        existing_wallet: ExistingWalletInfo,
        handler: Arc<dyn TonWalletSubscriptionHandler>,
    ) -> Result<Self> {
        let mut wallet_data = WalletData::default();

        let contract_subscription = ContractSubscription::subscribe(
            transport,
            existing_wallet.address,
            make_contract_state_handler(
                &handler,
                &existing_wallet.public_key,
                existing_wallet.wallet_type,
                &mut wallet_data,
            ),
            make_transactions_handler(&handler, existing_wallet.wallet_type),
        )
        .await?;

        Ok(Self {
            public_key: existing_wallet.public_key,
            wallet_type: existing_wallet.wallet_type,
            contract_subscription,
            handler,
            wallet_data,
        })
    }

    pub fn address(&self) -> &MsgAddressInt {
        self.contract_subscription.address()
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn wallet_type(&self) -> WalletType {
        self.wallet_type
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
        self.wallet_type.details()
    }

    pub fn get_unconfirmed_transactions(&self) -> &[MultisigPendingTransaction] {
        &self.wallet_data.unconfirmed_transactions
    }

    pub fn get_custodians(&self) -> &Option<Vec<UInt256>> {
        &self.wallet_data.custodians
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
                make_contract_state_handler(
                    &self.handler,
                    &self.public_key,
                    self.wallet_type,
                    &mut self.wallet_data,
                ),
                make_transactions_handler(&self.handler, self.wallet_type),
                make_message_sent_handler(&self.handler),
                make_message_expired_handler(&self.handler),
            )
            .await
    }

    pub async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()> {
        // TODO: update wallet data here

        let new_account_state = self.contract_subscription.handle_block(
            block,
            make_transactions_handler(&self.handler, self.wallet_type),
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
            .preload_transactions(
                from,
                make_transactions_handler(&self.handler, self.wallet_type),
            )
            .await
    }

    pub async fn estimate_fees(&mut self, message: &ton_block::Message) -> Result<u64> {
        self.contract_subscription.estimate_fees(message).await
    }
}

#[derive(Default)]
struct WalletData {
    custodians: Option<Vec<UInt256>>,
    unconfirmed_transactions: Vec<MultisigPendingTransaction>,
}

impl WalletData {
    fn update(
        &mut self,
        public_key: &PublicKey,
        wallet_type: WalletType,
        account_stuff: &ton_block::AccountStuff,
        contract_state: ContractState,
    ) -> Result<()> {
        let multisig_type = match wallet_type {
            WalletType::Multisig(multisig_type) => multisig_type,
            WalletType::WalletV3 => {
                if self.custodians.is_none() {
                    self.custodians = Some(vec![public_key.to_bytes().into()]);
                }
                return Ok(());
            }
        };

        let gen_timings = contract_state.gen_timings;
        let last_transaction_id = &contract_state
            .last_transaction_id
            .ok_or(TonWalletError::LastTransactionNotFound)?;

        // Extract custodians
        if self.custodians.is_none() {
            self.custodians = Some(multisig::get_custodians(
                multisig_type,
                Cow::Borrowed(account_stuff),
                gen_timings,
                last_transaction_id,
            )?);
        }

        let custodians = match &self.custodians {
            Some(custodians) => custodians,
            // SAFETY: `self.custodians` is guaranteed to be `Some` here.
            // This thing could be replaced with `get_or_insert_with` but value extraction returns `Result`
            None => unsafe { std::hint::unreachable_unchecked() },
        };

        // Skip pending transactions extraction for single custodian
        if custodians.len() < 2 {
            return Ok(());
        }

        // Extract pending transactions
        let pending_transactions = multisig::get_pending_transaction(
            multisig_type,
            Cow::Borrowed(account_stuff),
            gen_timings,
            last_transaction_id,
            custodians,
        )?;

        self.unconfirmed_transactions = pending_transactions;

        Ok(())
    }
}

pub fn extract_wallet_init_data(contract: &ExistingContract) -> Result<(PublicKey, WalletType)> {
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
        Ok((public_key, WalletType::Multisig(multisig_type)))
    } else if wallet_v3::is_wallet_v3(&code_hash) {
        let public_key =
            PublicKey::from_bytes(wallet_v3::InitData::try_from(data)?.public_key()).trust_me();
        Ok((public_key, WalletType::WalletV3))
    } else {
        Err(TonWalletError::InvalidContractType.into())
    }
}

pub fn get_wallet_custodians(
    contract: &ExistingContract,
    public_key: &ed25519_dalek::PublicKey,
    wallet_type: WalletType,
) -> Result<Vec<UInt256>> {
    let multisig_type = match wallet_type {
        WalletType::Multisig(multisig_type) => multisig_type,
        WalletType::WalletV3 => return Ok(vec![public_key.to_bytes().into()]),
    };

    let contract_state = contract.brief();
    let gen_timings = contract_state.gen_timings;
    let last_transaction_id = &contract_state
        .last_transaction_id
        .ok_or(TonWalletError::LastTransactionNotFound)?;

    let custodians = multisig::get_custodians(
        multisig_type,
        Cow::Borrowed(&contract.account),
        gen_timings,
        last_transaction_id,
    )?;
    Ok(custodians)
}

const WALLET_TYPES_BY_POPULARITY: [WalletType; 5] = [
    WalletType::Multisig(MultisigType::SurfWallet),
    WalletType::WalletV3,
    WalletType::Multisig(MultisigType::SafeMultisigWallet),
    WalletType::Multisig(MultisigType::SetcodeMultisigWallet),
    WalletType::Multisig(MultisigType::SafeMultisigWallet24h),
];

pub async fn find_existing_wallets(
    transport: &dyn Transport,
    public_key: &PublicKey,
    workchain_id: i8,
) -> Result<Vec<ExistingWalletInfo>> {
    use futures::stream::{FuturesUnordered, TryStreamExt};

    WALLET_TYPES_BY_POPULARITY
        .iter()
        .map(|&wallet_type| async move {
            let address = compute_address(public_key, wallet_type, workchain_id);

            let contract_state = transport.get_contract_state(&address).await?;

            Ok(ExistingWalletInfo {
                address,
                public_key: *public_key,
                wallet_type,
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
    pub wallet_type: WalletType,
    pub contract_state: ContractState,
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

fn make_contract_state_handler<'a, T>(
    handler: &'a T,
    public_key: &'a PublicKey,
    wallet_type: WalletType,
    wallet_data: &'a mut WalletData,
) -> impl FnMut(&RawContractState) + 'a
where
    T: AsRef<dyn TonWalletSubscriptionHandler>,
{
    move |contract_state| {
        if let RawContractState::Exists(contract_state) = contract_state {
            if let Err(e) = wallet_data.update(
                public_key,
                wallet_type,
                &contract_state.account,
                contract_state.brief(),
            ) {
                log::error!("{}", e);
            }
        }
        handler.as_ref().on_state_changed(contract_state.brief())
    }
}

fn make_transactions_handler<T>(
    handler: &'_ T,
    wallet_type: WalletType,
) -> impl FnMut(Vec<RawTransaction>, TransactionsBatchInfo) + '_
where
    T: AsRef<dyn TonWalletSubscriptionHandler>,
{
    move |transactions, batch_info| {
        let transactions = transactions
            .into_iter()
            .filter_map(move |transaction| {
                let data = parse_transaction_additional_info(&transaction.data, wallet_type);
                let transaction =
                    Transaction::try_from((transaction.hash, transaction.data)).ok()?;
                Some(TransactionWithData { transaction, data })
            })
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

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TonWalletDetails {
    pub requires_separate_deploy: bool,
    #[serde(with = "serde_u64")]
    pub min_amount: u64,
    pub supports_payload: bool,
    pub supports_multiple_owners: bool,
    pub expiration_time: u32,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum WalletType {
    Multisig(MultisigType),
    WalletV3,
}

impl WalletType {
    pub fn details(&self) -> TonWalletDetails {
        match self {
            WalletType::Multisig(multisig_type) => multisig::ton_wallet_details(*multisig_type),
            WalletType::WalletV3 => wallet_v3::DETAILS,
        }
    }
}

impl FromStr for WalletType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "WalletV3" => Self::WalletV3,
            s => Self::Multisig(MultisigType::from_str(s)?),
        })
    }
}

impl std::fmt::Display for WalletType {
    fn fmt(&self, f: &'_ mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WalletV3 => f.write_str("WalletV3"),
            Self::Multisig(multisig_type) => multisig_type.fmt(f),
        }
    }
}

pub fn compute_address(
    public_key: &PublicKey,
    wallet_type: WalletType,
    workchain_id: i8,
) -> MsgAddressInt {
    match wallet_type {
        WalletType::Multisig(multisig_type) => {
            multisig::compute_contract_address(public_key, multisig_type, workchain_id)
        }
        WalletType::WalletV3 => wallet_v3::compute_contract_address(public_key, workchain_id),
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
