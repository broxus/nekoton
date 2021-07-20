use std::cmp::Ordering;
use std::convert::TryFrom;

use anyhow::Result;
use chrono::Utc;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use ton_block::{Deserializable, MsgAddressInt};
use ton_token_abi::UnpackAbi;
use ton_types::UInt256;

use super::utils;
use crate::utils::*;

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum TransactionAdditionalInfo {
    /// Transaction with incoming message, which body is valid UTF-8 comment
    Comment(String),
    /// DePool notification
    DePoolOnRoundComplete(DePoolOnRoundCompleteNotification),
    /// DePool notification
    DePoolReceiveAnswer(DePoolReceiveAnswerNotification),
    /// Token wallet notification
    TokenWalletDeployed(TokenWalletDeployedNotification),
    /// Eth event notification
    EthEventStatusChanged(EthEventStatus),
    /// Ton event notification
    TonEventStatusChanged(TonEventStatus),
    /// User interaction with wallet contract
    WalletInteraction(WalletInteractionInfo),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletInteractionInfo {
    #[serde(with = "serde_optional_address")]
    pub recipient: Option<MsgAddressInt>,
    pub known_payload: Option<KnownPayload>,
    pub method: WalletInteractionMethod,
}

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum KnownPayload {
    Comment(String),
    TokenOutgoingTransfer(TokenOutgoingTransfer),
    TokenSwapBack(TokenSwapBack),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum WalletInteractionMethod {
    WalletV3Transfer,
    Multisig(Box<MultisigTransaction>),
}

#[derive(UnpackAbi, Clone, Debug, Serialize, Deserialize, Copy)]
#[abi(plain)]
pub struct DePoolOnRoundCompleteNotification {
    #[abi(uint64, name = "roundId")]
    #[serde(with = "serde_u64")]
    pub round_id: u64,
    #[abi(uint64, name = "reward")]
    #[serde(with = "serde_u64")]
    pub reward: u64,
    #[abi(uint64, name = "ordinaryStake")]
    #[serde(with = "serde_u64")]
    pub ordinary_stake: u64,
    #[abi(uint64, name = "vestingStake")]
    #[serde(with = "serde_u64")]
    pub vesting_stake: u64,
    #[abi(uint64, name = "lockStake")]
    #[serde(with = "serde_u64")]
    pub lock_stake: u64,
    #[abi(bool, name = "reinvest")]
    pub reinvest: bool,
    #[abi(uint8, name = "reason")]
    pub reason: u8,
}

#[derive(UnpackAbi, Clone, Debug, Serialize, Deserialize, Copy)]
#[abi(plain)]
pub struct DePoolReceiveAnswerNotification {
    #[abi(uint32, name = "errcode")]
    pub error_code: u32,
    #[abi(uint64, name = "comment")]
    #[serde(with = "serde_u64")]
    pub comment: u64,
}

#[derive(UnpackAbi, Clone, Debug, Serialize, Deserialize)]
#[abi(plain)]
pub struct TokenWalletDeployedNotification {
    #[abi(address, name = "root")]
    #[serde(with = "serde_address")]
    pub root_token_contract: MsgAddressInt,
}

crate::define_string_enum!(
    #[derive(
        Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, UnpackAbi,
    )]
    pub enum EthEventStatus {
        InProcess = 0,
        Confirmed = 1,
        Executed = 2,
        Rejected = 3,
    }
);

crate::define_string_enum!(
    #[derive(
        Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, UnpackAbi,
    )]
    pub enum TonEventStatus {
        InProcess = 0,
        Confirmed = 1,
        Rejected = 2,
    }
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MultisigTransaction {
    Send(MultisigSendTransaction),
    Submit(MultisigSubmitTransaction),
    Confirm(MultisigConfirmTransaction),
}

#[derive(UnpackAbi, Clone, Debug, PartialEq, Serialize, Deserialize, Copy)]
#[abi(plain)]
pub struct MultisigConfirmTransaction {
    #[serde(with = "serde_uint256")]
    pub custodian: UInt256,
    #[abi(uint64, name = "transactionId")]
    #[serde(with = "serde_u64")]
    pub transaction_id: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MultisigSubmitTransaction {
    #[serde(with = "serde_uint256")]
    pub custodian: UInt256,
    #[serde(with = "serde_address")]
    pub dest: MsgAddressInt,
    pub value: BigUint,
    pub bounce: bool,
    pub all_balance: bool,
    #[serde(with = "serde_cell")]
    pub payload: ton_types::Cell,
    #[serde(with = "serde_u64")]
    pub trans_id: u64,
}

#[derive(UnpackAbi, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[abi(plain)]
pub struct MultisigSendTransaction {
    #[abi(address)]
    #[serde(with = "serde_address")]
    pub dest: MsgAddressInt,
    #[abi(biguint128)]
    pub value: BigUint,
    #[abi(bool)]
    pub bounce: bool,
    #[abi(uint8)]
    pub flags: u8,
    #[abi(cell)]
    #[serde(with = "serde_cell")]
    pub payload: ton_types::Cell,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigPendingTransaction {
    #[serde(with = "serde_u64")]
    pub id: u64,
    #[serde(with = "serde_vec_uint256")]
    pub confirmations: Vec<UInt256>,
    pub signs_required: u8,
    pub signs_received: u8,
    #[serde(with = "serde_uint256")]
    pub creator: UInt256,
    pub index: u8,
    #[serde(with = "serde_address")]
    pub dest: MsgAddressInt,
    pub value: BigUint,
    pub send_flags: u16,
    #[serde(with = "serde_cell")]
    pub payload: ton_types::Cell,
    pub bounce: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum TokenWalletTransaction {
    IncomingTransfer(TokenIncomingTransfer),
    OutgoingTransfer(TokenOutgoingTransfer),
    SwapBack(TokenSwapBack),
    Accept(BigUint),
    TransferBounced(BigUint),
    SwapBackBounced(BigUint),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenIncomingTransfer {
    pub tokens: BigUint,
    /// Not the address of the token wallet, but the address of its owner
    #[serde(with = "serde_address")]
    pub sender_address: MsgAddressInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenOutgoingTransfer {
    pub to: TransferRecipient,
    pub tokens: BigUint,
}

#[derive(Clone, Debug)]
pub enum TransferRecipient {
    OwnerWallet(MsgAddressInt),
    TokenWallet(MsgAddressInt),
}

impl Serialize for TransferRecipient {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        #[derive(Serialize)]
        #[serde(transparent)]
        struct StoredItem<'a>(#[serde(with = "serde_address")] &'a MsgAddressInt);

        #[derive(Serialize)]
        #[serde(rename_all = "snake_case", tag = "type", content = "data")]
        enum StoredTransferRecipient<'a> {
            OwnerWallet(StoredItem<'a>),
            TokenWallet(StoredItem<'a>),
        }

        match self {
            TransferRecipient::OwnerWallet(address) => {
                StoredTransferRecipient::OwnerWallet(StoredItem(address))
            }
            TransferRecipient::TokenWallet(address) => {
                StoredTransferRecipient::TokenWallet(StoredItem(address))
            }
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TransferRecipient {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct StoredItem(#[serde(with = "serde_address")] MsgAddressInt);

        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case", tag = "type", content = "data")]
        enum StoredTransferRecipient {
            OwnerWallet(StoredItem),
            TokenWallet(StoredItem),
        }

        Ok(match StoredTransferRecipient::deserialize(deserializer)? {
            StoredTransferRecipient::OwnerWallet(item) => TransferRecipient::OwnerWallet(item.0),
            StoredTransferRecipient::TokenWallet(item) => TransferRecipient::TokenWallet(item.0),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenSwapBack {
    pub tokens: BigUint,
    /// ETH address
    pub to: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Copy)]
pub struct EthEventDetails {
    pub status: EthEventStatus,
    pub required_confirmation_count: u16,
    pub required_rejection_count: u16,
    pub confirmation_count: u16,
    pub rejection_count: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthEventData {
    #[serde(with = "serde_address")]
    pub root_token_contract: MsgAddressInt,
    pub tokens: BigUint,
}

#[derive(Clone, Debug, Serialize, Deserialize, Copy)]
pub struct TonEventDetails {
    pub status: TonEventStatus,
    pub required_confirmation_count: u16,
    pub required_rejection_count: u16,
    pub confirmation_count: u16,
    pub rejection_count: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TonEventData {
    #[serde(with = "serde_address")]
    pub root_token_contract: MsgAddressInt,
    pub tokens: BigUint,
    /// ETH address
    pub to: String,
}

crate::define_string_enum!(
    #[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    pub enum PollingMethod {
        /// Manual polling once a minute or by a click.
        /// Used when there are no pending transactions
        Manual,
        /// Block-walking for GQL or fast refresh for ADNL.
        /// Used when there are some pending transactions
        Reliable,
    }
);

crate::define_string_enum!(
    #[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    pub enum ReliableBehavior {
        /// Used for transports which doesn't support getting blocks directly (ADNL)
        IntensivePolling,
        /// Used for transports which support getting blocks directly (GQL)
        BlockWalking,
    }
);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Expiration {
    /// Message will never be expired. Not recommended to use
    Never,
    /// Interval after which the message will be invalid.
    /// Expiration timestamp should be refreshed as close to
    /// signing as possible
    Timeout(u32),
    /// The specific moment in time. Will stay the same after each
    /// refresh
    Timestamp(u32),
}

impl Expiration {
    pub fn timestamp(&self) -> u32 {
        match self {
            Self::Never => u32::MAX,
            Self::Timeout(timeout) => now() + timeout,
            &Self::Timestamp(timestamp) => timestamp,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpireAt {
    pub expiration: Expiration,
    pub timestamp: u32,
}

impl ExpireAt {
    pub fn new(expiration: Expiration) -> Self {
        Self {
            expiration,
            timestamp: expiration.timestamp(),
        }
    }

    pub fn new_from_millis(expiration: Expiration, time: u64) -> Self {
        let mut expire_at = Self {
            expiration,
            timestamp: 0,
        };
        expire_at.refresh_from_millis(time);
        expire_at
    }

    pub fn refresh(&mut self) -> bool {
        let old_timestamp = self.timestamp;
        self.timestamp = self.expiration.timestamp();
        self.timestamp != old_timestamp
    }

    pub fn refresh_from_millis(&mut self, time: u64) -> bool {
        let old_timestamp = self.timestamp;
        self.timestamp = if let Expiration::Timeout(timeout) = self.expiration {
            (time / 1000) as u32 + timeout
        } else {
            self.expiration.timestamp()
        };
        self.timestamp != old_timestamp
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Symbol {
    /// Full name
    pub name: String,

    /// Short name, e.g. USDT, DAI, etc.
    pub symbol: String,

    /// Fixed decimals count
    pub decimals: u8,

    /// Address of the root token contract
    #[serde(with = "serde_address")]
    pub root_token_contract: MsgAddressInt,
}

crate::define_string_enum!(
    #[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    pub enum TokenWalletVersion {
        /// First stable iteration of token wallets.
        /// [implementation](https://github.com/broxus/ton-eth-bridge-token-contracts/commit/34e466bd42789413f02aeec0051b9d1212fe6de9)
        Tip3v1,
        /// Second iteration of token wallets with extended transfer messages payload.
        /// [implementation](https://github.com/broxus/ton-eth-bridge-token-contracts/commit/97ee321a2d8619372cdd2db8df30bd543e5c7417)
        Tip3v2,
        /// Third iteration of token wallets with updated compiler version and responsible getters.
        /// [implementation](https://github.com/broxus/ton-eth-bridge-token-contracts/commit/e7ef0506081fb36de94ea92d1bc1c50888ca65bc)
        Tip3v3,
        /// Third iteration of token wallets, but with fixed bugs
        /// [implementation](https://github.com/broxus/ton-eth-bridge-token-contracts/commit/74905260499d79cf7cb0d89a6eb572176fc1fcd5)
        Tip3v4,
    }
);

impl TryFrom<u32> for TokenWalletVersion {
    type Error = anyhow::Error;

    fn try_from(version: u32) -> Result<Self, Self::Error> {
        Ok(match version {
            1 => Self::Tip3v1,
            2 => Self::Tip3v2,
            3 => Self::Tip3v3,
            4 => Self::Tip3v4,
            _ => return Err(UnknownTokenWalletVersion.into()),
        })
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Unknown token wallet version")]
struct UnknownTokenWalletVersion;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenWalletDetails {
    /// Linked root token contract address
    #[serde(with = "serde_address")]
    pub root_address: MsgAddressInt,
    /// Owner wallet address
    #[serde(with = "serde_address")]
    pub owner_address: MsgAddressInt,
    #[serde(skip)]
    pub code: Option<ton_types::Cell>,
    #[serde(skip)]
    pub wallet_public_key: UInt256,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RootTokenContractDetails {
    /// Token ecosystem version
    pub version: TokenWalletVersion,
    /// Full currency name
    pub name: String,
    /// Short currency name
    pub symbol: String,
    /// Decimals
    pub decimals: u8,
    /// Root owner contract address. Used as proxy address in Tip3v1
    #[serde(with = "serde_address")]
    pub owner_address: MsgAddressInt,
    #[serde(with = "serde_biguint")]
    pub total_supply: BigUint,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Copy)]
pub struct ContractState {
    /// Full account balance in nano TON
    #[serde(with = "serde_u64")]
    pub balance: u64,
    /// At what point was this state obtained
    pub gen_timings: GenTimings,
    /// Last transaction id
    pub last_transaction_id: Option<LastTransactionId>,
    /// Whether the contract is deployed
    pub is_deployed: bool,
}

impl PartialEq for ContractState {
    fn eq(&self, other: &Self) -> bool {
        // Ignore timings change

        self.balance == other.balance
            && self.last_transaction_id == other.last_transaction_id
            && self.is_deployed == other.is_deployed
    }
}

impl Eq for ContractState {}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum GenTimings {
    /// There is no way to determine the point in time at which this specific state was obtained
    Unknown,
    /// There is a known point in time at which this specific state was obtained
    Known {
        #[serde(with = "serde_u64")]
        gen_lt: u64,
        gen_utime: u32,
    },
}

impl Default for GenTimings {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Additional estimated lag for the pending message to be expired
pub const GEN_TIMINGS_ALLOWABLE_INTERVAL: u32 = 30;

impl GenTimings {
    pub fn current_utime(&self) -> u32 {
        match *self {
            GenTimings::Unknown => {
                // TODO: split optimistic and pessimistic predictions for unknown timings
                Utc::now().timestamp() as u32 - GEN_TIMINGS_ALLOWABLE_INTERVAL
            }
            GenTimings::Known { gen_utime, .. } => gen_utime,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingTransaction {
    /// External message hash
    #[serde(with = "serde_uint256")]
    pub message_hash: UInt256,
    /// Hash of the external message body. Used to identify message in executed transactions
    #[serde(with = "serde_uint256")]
    pub body_hash: UInt256,
    /// Incoming message source
    #[serde(with = "serde_optional_address")]
    pub src: Option<MsgAddressInt>,
    /// Expiration timestamp, unixtime
    pub expire_at: u32,
}

impl PartialEq<Transaction> for PendingTransaction {
    fn eq(&self, other: &Transaction) -> bool {
        self.expire_at < other.created_at
            && self.src == other.in_msg.src
            && matches!(&other.in_msg.body, Some(body) if self.body_hash == body.hash)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Internal,
    External,
}

/// Transaction with additional data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionWithData<T> {
    pub transaction: Transaction,
    pub data: Option<T>,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct TransactionsBatchInfo {
    /// The smallest lt in a group
    #[serde(with = "serde_u64")]
    pub min_lt: u64,
    /// Maximum lt in a group
    #[serde(with = "serde_u64")]
    pub max_lt: u64,
    /// Whether this batch was from the preload request
    pub old: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Full transaction id
    pub id: TransactionId,
    /// Previous transaction id. `None` for last transaction
    pub prev_trans_id: Option<TransactionId>,
    /// Transaction unix timestamp
    pub created_at: u32,
    /// Whether transaction execution was unsuccessful
    pub aborted: bool,
    /// Action phrase exit code. `None` if action phase was skipped
    pub result_code: Option<i32>,
    /// Account status before transaction execution
    pub orig_status: AccountStatus,
    /// Account status after transaction execution
    pub end_status: AccountStatus,
    /// Sum of fees from all execution stages
    #[serde(with = "serde_u64")]
    pub total_fees: u64,
    /// Incoming message
    pub in_msg: Message,
    /// Outgoing messages
    pub out_msgs: Vec<Message>,
}

impl TryFrom<(UInt256, ton_block::Transaction)> for Transaction {
    type Error = TransactionError;

    fn try_from((hash, mut data): (UInt256, ton_block::Transaction)) -> Result<Self, Self::Error> {
        let desc = if let ton_block::TransactionDescr::Ordinary(desc) = data
            .description
            .read_struct()
            .map_err(|_| TransactionError::InvalidStructure)?
        {
            desc
        } else {
            return Err(TransactionError::Unsupported);
        };

        let total_fees = utils::compute_total_transaction_fees(&data, &desc);

        let in_msg = match data.in_msg.take() {
            Some(message) => message
                .read_struct()
                .map(Message::from)
                .map_err(|_| TransactionError::InvalidStructure)?,
            None => return Err(TransactionError::Unsupported),
        };

        let result_code = desc.action.map(|action| action.result_code);

        let mut out_msgs = Vec::new();
        data.out_msgs
            .iterate_slices(|slice| {
                if let Ok(message) = slice
                    .reference(0)
                    .and_then(ton_block::Message::construct_from_cell)
                    .map(Message::from)
                {
                    out_msgs.push(message);
                }
                Ok(true)
            })
            .map_err(|_| TransactionError::InvalidStructure)?;

        Ok(Self {
            id: TransactionId { lt: data.lt, hash },
            prev_trans_id: (data.prev_trans_lt != 0).then(|| TransactionId {
                lt: data.prev_trans_lt,
                hash: data.prev_trans_hash,
            }),
            created_at: data.now,
            aborted: desc.aborted,
            result_code,
            orig_status: data.orig_status.into(),
            end_status: data.end_status.into(),
            total_fees,
            in_msg,
            out_msgs,
        })
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum TransactionError {
    #[error("Invalid transaction structure")]
    InvalidStructure,
    #[error("Unsupported transaction type")]
    Unsupported,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    /// Account exists and has a positive balance
    Uninit,
    /// Account exists, but is frozen
    Frozen,
    /// Account exists, has a deployed contract code and has a positive balance
    Active,
    /// Account doesn't exist
    Nonexist,
}

impl From<ton_block::AccountStatus> for AccountStatus {
    fn from(s: ton_block::AccountStatus) -> Self {
        match s {
            ton_block::AccountStatus::AccStateUninit => AccountStatus::Uninit,
            ton_block::AccountStatus::AccStateFrozen => AccountStatus::Frozen,
            ton_block::AccountStatus::AccStateActive => AccountStatus::Active,
            ton_block::AccountStatus::AccStateNonexist => AccountStatus::Nonexist,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Message {
    /// Source message address, `None` for external messages
    #[serde(with = "serde_optional_address")]
    pub src: Option<MsgAddressInt>,

    /// Destination message address, `None` for outbound messages
    #[serde(with = "serde_optional_address")]
    pub dst: Option<MsgAddressInt>,

    /// Message value in nano TON
    #[serde(with = "serde_u64")]
    pub value: u64,

    /// Message body
    pub body: Option<MessageBody>,

    /// Whether this message will be bounced on unsuccessful execution.
    pub bounce: bool,

    /// Whether this message was bounced during unsuccessful execution.
    /// Only relevant for internal messages
    pub bounced: bool,
}

impl From<ton_block::Message> for Message {
    fn from(s: ton_block::Message) -> Self {
        let body = s.body().and_then(|body| MessageBody::try_from(body).ok());

        match s.header() {
            ton_block::CommonMsgInfo::IntMsgInfo(header) => Message {
                src: match &header.src {
                    ton_block::MsgAddressIntOrNone::Some(addr) => Some(addr.clone()),
                    ton_block::MsgAddressIntOrNone::None => None,
                },
                dst: Some(header.dst.clone()),
                value: header.value.grams.0 as u64,
                body,
                bounce: header.bounce,
                bounced: header.bounced,
            },
            ton_block::CommonMsgInfo::ExtInMsgInfo(header) => Message {
                src: None,
                dst: Some(header.dst.clone()),
                body,
                ..Default::default()
            },
            ton_block::CommonMsgInfo::ExtOutMsgInfo(header) => Message {
                src: match &header.src {
                    ton_block::MsgAddressIntOrNone::Some(addr) => Some(addr.clone()),
                    ton_block::MsgAddressIntOrNone::None => None,
                },
                body,
                ..Default::default()
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageBody {
    /// Hash of body in cell representation
    #[serde(with = "serde_uint256")]
    pub hash: UInt256,
    /// Base64 encoded message body
    pub data: String,
}

impl MessageBody {
    pub fn decode(&self) -> Result<ton_types::Cell> {
        let bytes = base64::decode(&self.data)?;
        let cell = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(&bytes))
            .map_err(|_| MessageBodyError::FailedToDeserialize)?;
        Ok(cell)
    }
}

impl TryFrom<ton_types::SliceData> for MessageBody {
    type Error = MessageBodyError;

    fn try_from(s: ton_types::SliceData) -> Result<Self, Self::Error> {
        let cell = s.into_cell();
        let hash = cell.repr_hash();
        let bytes =
            ton_types::serialize_toc(&cell).map_err(|_| MessageBodyError::FailedToSerialize)?;
        Ok(Self {
            hash,
            data: base64::encode(bytes),
        })
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum MessageBodyError {
    #[error("Failed to serialize data")]
    FailedToSerialize,
    #[error("Failed to deserialize data")]
    FailedToDeserialize,
}

#[derive(Debug, Copy, Clone, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type", content = "data")]
pub enum LastTransactionId {
    Exact(TransactionId),
    Inexact {
        #[serde(with = "serde_u64")]
        latest_lt: u64,
    },
}

impl LastTransactionId {
    /// Whether the exact id is known
    pub fn is_exact(&self) -> bool {
        matches!(self, Self::Exact(_))
    }

    /// Converts last transaction id into real or fake id
    pub fn to_transaction_id(self) -> TransactionId {
        match self {
            Self::Exact(id) => id,
            Self::Inexact { latest_lt } => TransactionId {
                lt: latest_lt,
                hash: Default::default(),
            },
        }
    }
}

impl PartialEq for LastTransactionId {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact(left), Self::Exact(right)) => left == right,
            (Self::Inexact { latest_lt: left }, Self::Inexact { latest_lt: right }) => {
                left == right
            }
            _ => false,
        }
    }
}

impl PartialOrd for LastTransactionId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LastTransactionId {
    fn cmp(&self, other: &Self) -> Ordering {
        let left = match self {
            Self::Exact(id) => &id.lt,
            Self::Inexact { latest_lt } => latest_lt,
        };
        let right = match other {
            Self::Exact(id) => &id.lt,
            Self::Inexact { latest_lt } => latest_lt,
        };
        left.cmp(right)
    }
}

#[derive(Debug, Copy, Clone, Eq, Serialize, Deserialize)]
pub struct TransactionId {
    #[serde(with = "serde_u64")]
    pub lt: u64,
    #[serde(with = "serde_uint256")]
    pub hash: UInt256,
}

impl PartialEq for TransactionId {
    fn eq(&self, other: &Self) -> bool {
        self.lt == other.lt
    }
}

impl PartialOrd for TransactionId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.lt.cmp(&other.lt)
    }
}

#[derive(thiserror::Error, Debug)]
pub(super) enum AccountSubscriptionError {
    #[error("Invalid message destination")]
    InvalidMessageDestination,
    #[error("Invalid message type")]
    InvalidMessageType,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_transaction() {
        let transaction =  ton_block::Transaction::construct_from_base64("te6ccgECCgEAAmIAA7VxDMDpxVKoQf1ESN4flYWnx79MwznjFCnHv2LMYnj5e/AAAMAPptS0HL7tNWkkUnpwkWevWy0v6QllFeZdkxpKd3jABu53GMiwAADABeYcjBYH/izgADRpb9DoBQQBAhEMgEHGGW16hEADAgBvyYehIEwUWEAAAAAAAAIAAAAAAAJdRbUJwB114ymQlNQVCfa9Moy2h4xlzAjFN0wo4BiqckBQGUwAnUF2QxOIAAAAAAAAAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAgnIKnXiVk1PWmbnJrrJ8ZuP6tVF8xWwdT4FzwpwwbcybITXW+aJKu2Ai+6iWudx7E+cmmtyYoMFlMnA6RJvjslElAgHgCAYBAd8HAMtoACGYHTiqVQg/qIkbw/KwtPj36ZhnPGKFOPfsWYxPHy9/AC7y/frS28SA7otT/U3XeMKVAioEwv3n4cO+8/UnsFk6VAnHZSQABhRYYAAAGAH02paEwP/FnAVWDH6AAAABKgXyAEAB34gAIZgdOKpVCD+oiRvD8rC0+PfpmGc8YoU49+xZjE8fL34FEnWHwu7iFVw1r2O1eQN6i3g5Ib9nJIGpQqRtpYG36Pjrmo9/vgPWf5ev1vhedfPUgkaxeInhVroDrGaLYfhoEl1JbFYH/i5IAAADOBwJAIJiAF3l+/Wlt4kB3Ran+puu8YUqBFQJhfvPw4d95+pPYLJ0qBOOykgAAAAAAAAAAAAAAAAAAAqsGP0AAAACVAvkAA==").unwrap();
        let parsed = Transaction::try_from((Default::default(), transaction)).unwrap();
        assert!(parsed.in_msg.body.is_some())
    }
}
