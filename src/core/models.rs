use std::cmp::Ordering;
use std::convert::TryFrom;

use anyhow::Result;
use chrono::Utc;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use ton_block::{Deserializable, MsgAddressInt};
use ton_types::UInt256;

use super::utils;
use crate::utils::*;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PollingMethod {
    /// Manual polling once a minute or by a click.
    /// Used when there are no pending transactions
    Manual,
    /// Block-walking for GQL or fast refresh for ADNL.
    /// Used when there are some pending transactions
    Reliable,
}

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
    /// Symbol name, e.g. USDT, DAI, etc.
    pub name: String,

    /// Fixed decimals count
    pub decimals: u8,

    /// Address of the root token contract
    #[serde(with = "serde_address")]
    pub root_token_contract: MsgAddressInt,
}

pub struct WalletState {
    /// Brief account state
    pub account_state: AccountState,
    /// List of the latest transactions (not complete, only about 16 elements)
    pub last_transactions: Vec<Transaction>,
    /// List of pending transactions
    pub pending_transactions: Vec<PendingTransaction>,
}

#[derive(Debug, Copy, Clone, Eq, Ord, PartialOrd, PartialEq, Hash, Serialize, Deserialize)]
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
}

impl TryFrom<u32> for TokenWalletVersion {
    type Error = anyhow::Error;

    fn try_from(version: u32) -> Result<Self, Self::Error> {
        Ok(match version {
            1 => Self::Tip3v1,
            2 => Self::Tip3v2,
            3 => Self::Tip3v3,
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenWalletState {
    /// Balance in tokens
    pub balance: BigUint,
    /// Underlying contract state
    pub account_state: AccountState,
}

impl PartialEq for TokenWalletState {
    fn eq(&self, other: &Self) -> bool {
        self.account_state.eq(&other.account_state)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountState {
    /// Full account balance in nano TON
    pub balance: u64,
    /// At what point was this state obtained
    pub gen_timings: GenTimings,
    /// Last transaction id
    pub last_transaction_id: Option<LastTransactionId>,
    /// Whether the contract is deployed
    pub is_deployed: bool,
}

impl PartialEq for AccountState {
    fn eq(&self, other: &Self) -> bool {
        match (&self.last_transaction_id, &other.last_transaction_id) {
            (None, Some(_)) => true,
            (Some(current), Some(new)) if current < new => true,
            _ => false,
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum GenTimings {
    /// There is no way to determine the point in time at which this specific state was obtained
    Unknown,
    /// There is a known point in time at which this specific state was obtained
    Known { gen_lt: u64, gen_utime: u32 },
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
    /// Incoming message source
    #[serde(with = "serde_optional_address")]
    pub src: Option<MsgAddressInt>,
    /// Hash of the external message body. Used to identify message in executed transactions
    #[serde(with = "serde_uint256")]
    pub body_hash: UInt256,
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

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct TransactionsBatchInfo {
    /// The smallest lt in a group
    pub min_lt: u64,
    /// Maximum lt in a group
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
    /// Account status before transaction execution
    pub orig_status: AccountStatus,
    /// Account status after transaction execution
    pub end_status: AccountStatus,
    /// Sum of fees from all execution stages
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

        // TODO: parse and store tvm execution code?

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
            orig_status: data.orig_status.into(),
            end_status: data.end_status.into(),
            total_fees,
            in_msg,
            out_msgs,
        })
    }
}

#[derive(thiserror::Error, Debug)]
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

#[derive(thiserror::Error, Debug)]
pub enum MessageBodyError {
    #[error("Failed to serialize data")]
    FailedToSerialize,
    #[error("Failed to deserialize data")]
    FailedToDeserialize,
}

#[derive(Debug, Copy, Clone, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum LastTransactionId {
    Exact(TransactionId),
    Inexact { latest_lt: u64 },
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
