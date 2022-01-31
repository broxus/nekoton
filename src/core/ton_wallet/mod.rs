use std::borrow::Cow;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use serde::{Deserialize, Serialize};
use ton_block::MsgAddressInt;
use ton_types::{SliceData, UInt256};

use nekoton_abi::*;
use nekoton_utils::*;

pub use self::multisig::MultisigType;
use super::models::{
    ContractState, Expiration, MessageFlags, MultisigPendingTransaction, PendingTransaction,
    Transaction, TransactionAdditionalInfo, TransactionWithData, TransactionsBatchInfo,
};
use super::{ContractSubscription, PollingMethod};
use crate::core::parsing::*;
use crate::core::InternalMessage;
use crate::crypto::UnsignedMessage;
use crate::transport::models::{ExistingContract, RawContractState, RawTransaction};
use crate::transport::Transport;

pub mod highload_wallet_v2;
pub mod multisig;
pub mod wallet_v3;

pub const DEFAULT_WORKCHAIN: i8 = 0;

pub struct TonWallet {
    clock: Arc<dyn Clock>,
    public_key: PublicKey,
    wallet_type: WalletType,
    contract_subscription: ContractSubscription,
    handler: Arc<dyn TonWalletSubscriptionHandler>,
    wallet_data: WalletData,
}

impl TonWallet {
    pub async fn subscribe(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        workchain: i8,
        public_key: PublicKey,
        wallet_type: WalletType,
        handler: Arc<dyn TonWalletSubscriptionHandler>,
    ) -> Result<Self> {
        let address = compute_address(&public_key, wallet_type, workchain);

        let mut wallet_data = WalletData::default();

        let contract_subscription = ContractSubscription::subscribe(
            clock.clone(),
            transport,
            address,
            make_contract_state_handler(
                clock.as_ref(),
                &handler,
                &public_key,
                wallet_type,
                &mut wallet_data,
            ),
            make_transactions_handler(&handler, wallet_type),
        )
        .await?;

        Ok(Self {
            clock,
            public_key,
            wallet_type,
            contract_subscription,
            handler,
            wallet_data,
        })
    }

    pub async fn subscribe_by_address(
        clock: Arc<dyn Clock>,
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
            clock.clone(),
            transport,
            address,
            make_contract_state_handler(
                clock.as_ref(),
                &handler,
                &public_key,
                wallet_type,
                &mut wallet_data,
            ),
            make_transactions_handler(&handler, wallet_type),
        )
        .await?;

        Ok(Self {
            clock,
            public_key,
            wallet_type,
            contract_subscription,
            handler,
            wallet_data,
        })
    }

    pub async fn subscribe_by_existing(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        existing_wallet: ExistingWalletInfo,
        handler: Arc<dyn TonWalletSubscriptionHandler>,
    ) -> Result<Self> {
        let mut wallet_data = WalletData::default();

        let contract_subscription = ContractSubscription::subscribe(
            clock.clone(),
            transport,
            existing_wallet.address,
            make_contract_state_handler(
                clock.as_ref(),
                &handler,
                &existing_wallet.public_key,
                existing_wallet.wallet_type,
                &mut wallet_data,
            ),
            make_transactions_handler(&handler, existing_wallet.wallet_type),
        )
        .await?;

        Ok(Self {
            clock,
            public_key: existing_wallet.public_key,
            wallet_type: existing_wallet.wallet_type,
            contract_subscription,
            handler,
            wallet_data,
        })
    }

    pub fn contract_subscription(&self) -> &ContractSubscription {
        &self.contract_subscription
    }

    pub fn workchain(&self) -> i8 {
        self.contract_subscription.address().workchain_id() as i8
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

    pub fn prepare_deploy(&self, expiration: Expiration) -> Result<Box<dyn UnsignedMessage>> {
        match self.wallet_type {
            WalletType::WalletV3 => wallet_v3::prepare_deploy(
                self.clock.as_ref(),
                &self.public_key,
                self.workchain(),
                expiration,
            ),
            WalletType::Multisig(multisig_type) => multisig::prepare_deploy(
                self.clock.as_ref(),
                &self.public_key,
                multisig_type,
                self.workchain(),
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
        match self.wallet_type {
            WalletType::Multisig(multisig_type) => multisig::prepare_deploy(
                self.clock.as_ref(),
                &self.public_key,
                multisig_type,
                self.workchain(),
                expiration,
                custodians,
                req_confirms,
            ),
            WalletType::WalletV3 => Err(TonWalletError::InvalidContractType.into()),
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
        let flags = MessageFlags::default();

        match self.wallet_type {
            WalletType::Multisig(_) => {
                match &current_state.storage.state {
                    ton_block::AccountState::AccountFrozen { .. } => {
                        return Err(TonWalletError::AccountIsFrozen.into())
                    }
                    ton_block::AccountState::AccountUninit => {
                        return Ok(TransferAction::DeployFirst)
                    }
                    ton_block::AccountState::AccountActive { .. } => {}
                };

                self.wallet_data.update(
                    self.clock.as_ref(),
                    &self.public_key,
                    self.wallet_type,
                    current_state,
                )?;

                let has_multiple_owners = match &self.wallet_data.custodians {
                    Some(custodians) => custodians.len() > 1,
                    None => return Err(TonWalletError::CustodiansNotFound.into()),
                };

                multisig::prepare_transfer(
                    self.clock.as_ref(),
                    public_key,
                    has_multiple_owners,
                    self.address().clone(),
                    destination,
                    amount,
                    flags.into(),
                    bounce,
                    body,
                    expiration,
                )
            }
            WalletType::WalletV3 => wallet_v3::prepare_transfer(
                self.clock.as_ref(),
                public_key,
                current_state,
                destination,
                amount,
                flags.into(),
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
        match self.wallet_type {
            WalletType::Multisig(multisig_type) => {
                let has_pending_transaction = multisig::find_pending_transaction(
                    self.clock.as_ref(),
                    multisig_type,
                    Cow::Borrowed(current_state),
                    transaction_id,
                )?;
                if !has_pending_transaction {
                    return Err(TonWalletError::PendingTransactionNotFound.into());
                }

                multisig::prepare_confirm_transaction(
                    self.clock.as_ref(),
                    public_key,
                    self.address().clone(),
                    transaction_id,
                    expiration,
                )
            }
            WalletType::WalletV3 => Err(TonWalletError::PendingTransactionNotFound.into()),
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
                make_contract_state_handler(
                    self.clock.as_ref(),
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

    pub async fn estimate_fees(&mut self, message: &ton_block::Message) -> Result<u128> {
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
        clock: &dyn Clock,
        public_key: &PublicKey,
        wallet_type: WalletType,
        account_stuff: &ton_block::AccountStuff,
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

        // Extract custodians
        if self.custodians.is_none() {
            self.custodians = Some(multisig::get_custodians(
                clock,
                multisig_type,
                Cow::Borrowed(account_stuff),
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
            clock,
            multisig_type,
            Cow::Borrowed(account_stuff),
            custodians,
        )?;

        self.unconfirmed_transactions = pending_transactions;

        Ok(())
    }
}

pub fn extract_wallet_init_data(contract: &ExistingContract) -> Result<(PublicKey, WalletType)> {
    let (code, data) = match &contract.account.storage.state {
        ton_block::AccountState::AccountActive {
            state_init:
                ton_block::StateInit {
                    code: Some(code),
                    data: Some(data),
                    ..
                },
            ..
        } => (code, data),
        _ => return Err(TonWalletError::AccountNotExists.into()),
    };

    let code_hash = code.repr_hash();
    if let Some(multisig_type) = multisig::guess_multisig_type(&code_hash) {
        let public_key = extract_public_key(&contract.account)?;
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
    clock: &dyn Clock,
    contract: &ExistingContract,
    public_key: &ed25519_dalek::PublicKey,
    wallet_type: WalletType,
) -> Result<Vec<UInt256>> {
    let multisig_type = match wallet_type {
        WalletType::Multisig(multisig_type) => multisig_type,
        WalletType::WalletV3 => return Ok(vec![public_key.to_bytes().into()]),
    };

    let custodians =
        multisig::get_custodians(clock, multisig_type, Cow::Borrowed(&contract.account))?;
    Ok(custodians)
}

const WALLET_TYPES_BY_POPULARITY: [WalletType; 6] = [
    WalletType::Multisig(MultisigType::SurfWallet),
    WalletType::WalletV3,
    WalletType::Multisig(MultisigType::SafeMultisigWallet),
    WalletType::Multisig(MultisigType::SetcodeMultisigWallet),
    WalletType::Multisig(MultisigType::SafeMultisigWallet24h),
    WalletType::Multisig(MultisigType::BridgeMultisigWallet),
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
    #[error("Custodians not found")]
    CustodiansNotFound,
    #[error("Pending transactino not found")]
    PendingTransactionNotFound,
}

fn make_contract_state_handler<'a, T>(
    clock: &'a dyn Clock,
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
            if let Err(e) =
                wallet_data.update(clock, public_key, wallet_type, &contract_state.account)
            {
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
    #[serde(with = "serde_string")]
    pub min_amount: u64,
    pub supports_payload: bool,
    pub supports_multiple_owners: bool,
    pub expiration_time: u32,
}

#[derive(Clone)]
pub enum TransferAction {
    DeployFirst,
    Sign(Box<dyn UnsignedMessage>),
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

/// Zerostate hack
pub fn map_special_account(
    public_key: &PublicKey,
    multisig_type: WalletType,
    workchain_id: i8,
) -> Option<MsgAddressInt> {
    const GIVER_7_PUBKEY: [u8; 32] = [
        0xce, 0x4a, 0x6b, 0x49, 0x93, 0xd6, 0x6b, 0xb0, 0xc8, 0x54, 0x16, 0xc2, 0xc4, 0x61, 0x53,
        0x92, 0xda, 0x2d, 0x58, 0x03, 0x56, 0xbf, 0x96, 0xef, 0x2a, 0x87, 0x4e, 0x9c, 0x18, 0xed,
        0x18, 0x57,
    ];
    const GIVER_8_PUBKEY: [u8; 32] = [
        0x6b, 0x41, 0xf3, 0xe6, 0x2d, 0xab, 0x18, 0x85, 0xc8, 0x47, 0x2d, 0xf9, 0xb0, 0xf6, 0x52,
        0x9a, 0x9c, 0xe5, 0x44, 0x8b, 0x2c, 0x41, 0x6e, 0x65, 0xe4, 0x43, 0x17, 0x8d, 0x23, 0xfe,
        0xb5, 0x2d,
    ];
    const GIVER_9_PUBKEY: [u8; 32] = [
        0xcd, 0x58, 0x37, 0xa9, 0x13, 0xba, 0x6e, 0x66, 0x63, 0x80, 0x97, 0x08, 0xf9, 0x95, 0x8f,
        0x80, 0xd2, 0xd8, 0x0d, 0xe6, 0x67, 0x51, 0x76, 0x03, 0x35, 0x87, 0xb5, 0xa6, 0x00, 0x24,
        0xd2, 0xc8,
    ];

    if multisig_type != WalletType::Multisig(MultisigType::SetcodeMultisigWallet)
        || workchain_id != -1
    {
        return None;
    }

    match *public_key.as_bytes() {
        GIVER_7_PUBKEY => MsgAddressInt::from_str(
            "-1:7777777777777777777777777777777777777777777777777777777777777777",
        )
        .ok(),
        GIVER_8_PUBKEY => MsgAddressInt::from_str(
            "-1:8888888888888888888888888888888888888888888888888888888888888888",
        )
        .ok(),
        GIVER_9_PUBKEY => MsgAddressInt::from_str(
            "-1:9999999999999999999999999999999999999999999999999999999999999999",
        )
        .ok(),
        _ => None,
    }
}

pub fn compute_address(
    public_key: &PublicKey,
    wallet_type: WalletType,
    workchain_id: i8,
) -> MsgAddressInt {
    if let Some(address) = map_special_account(public_key, wallet_type, workchain_id) {
        return address;
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_special_address_computation() {
        let pairs = [
            (
                "ce4a6b4993d66bb0c85416c2c4615392da2d580356bf96ef2a874e9c18ed1857",
                "-1:7777777777777777777777777777777777777777777777777777777777777777",
            ),
            (
                "6b41f3e62dab1885c8472df9b0f6529a9ce5448b2c416e65e443178d23feb52d",
                "-1:8888888888888888888888888888888888888888888888888888888888888888",
            ),
            (
                "cd5837a913ba6e6663809708f9958f80d2d80de6675176033587b5a60024d2c8",
                "-1:9999999999999999999999999999999999999999999999999999999999999999",
            ),
        ];

        for (public_key, target_address) in pairs {
            let public_key =
                ed25519_dalek::PublicKey::from_bytes(&hex::decode(public_key).unwrap()).unwrap();
            let address = compute_address(
                &public_key,
                WalletType::Multisig(MultisigType::SetcodeMultisigWallet),
                -1,
            );
            assert_eq!(address.to_string(), target_address);
        }
    }
}
