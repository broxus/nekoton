use std::convert::TryFrom;

use anyhow::Result;
use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ton_block::{Deserializable, MsgAddressInt};
use ton_types::UInt256;

use nekoton_abi::*;
use nekoton_utils::*;

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
#[serde(rename_all = "camelCase")]
pub struct WalletInteractionInfo {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_optional_address"
    )]
    pub recipient: Option<MsgAddressInt>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
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

#[derive(UnpackAbiPlain, Clone, Debug, Serialize, Deserialize, Copy)]
#[serde(rename_all = "camelCase")]
pub struct DePoolOnRoundCompleteNotification {
    #[abi(uint64, name = "roundId")]
    #[serde(with = "serde_string")]
    pub round_id: u64,

    #[abi(uint64, name = "reward")]
    #[serde(with = "serde_string")]
    pub reward: u64,

    #[abi(uint64, name = "ordinaryStake")]
    #[serde(with = "serde_string")]
    pub ordinary_stake: u64,

    #[abi(uint64, name = "vestingStake")]
    #[serde(with = "serde_string")]
    pub vesting_stake: u64,

    #[abi(uint64, name = "lockStake")]
    #[serde(with = "serde_string")]
    pub lock_stake: u64,

    #[abi(bool, name = "reinvest")]
    pub reinvest: bool,

    #[abi(uint8, name = "reason")]
    pub reason: u8,
}

#[derive(UnpackAbiPlain, Clone, Debug, Serialize, Deserialize, Copy)]
#[serde(rename_all = "camelCase")]
pub struct DePoolReceiveAnswerNotification {
    #[abi(uint32, name = "errcode")]
    pub error_code: u32,

    #[abi(uint64, name = "comment")]
    #[serde(with = "serde_string")]
    pub comment: u64,
}

#[derive(UnpackAbiPlain, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenWalletDeployedNotification {
    #[abi(address, name = "root")]
    #[serde(with = "serde_address")]
    pub root_token_contract: MsgAddressInt,
}

define_string_enum!(
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, UnpackAbi)]
    pub enum EthEventStatus {
        InProcess = 0,
        Confirmed = 1,
        Executed = 2,
        Rejected = 3,
    }
);

define_string_enum!(
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, UnpackAbi)]
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

#[derive(UnpackAbiPlain, Clone, Debug, PartialEq, Serialize, Deserialize, Copy)]
#[serde(rename_all = "camelCase")]
pub struct MultisigConfirmTransaction {
    #[serde(with = "serde_uint256")]
    pub custodian: UInt256,

    #[abi(uint64, name = "transactionId")]
    #[serde(with = "serde_string")]
    pub transaction_id: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultisigSubmitTransaction {
    #[serde(with = "serde_uint256")]
    pub custodian: UInt256,

    #[serde(with = "serde_address")]
    pub dest: MsgAddressInt,

    #[serde(with = "serde_string")]
    pub value: BigUint,

    pub bounce: bool,

    pub all_balance: bool,

    #[serde(with = "serde_cell")]
    pub payload: ton_types::Cell,

    #[serde(with = "serde_string")]
    pub trans_id: u64,
}

#[derive(UnpackAbiPlain, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MultisigSendTransaction {
    #[abi(address)]
    #[serde(with = "serde_address")]
    pub dest: MsgAddressInt,

    #[abi(with = "nekoton_abi::uint128_number")]
    #[serde(with = "serde_string")]
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
    #[serde(with = "serde_string")]
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

    #[serde(with = "serde_string")]
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
#[serde(rename_all = "camelCase")]
pub struct TokenIncomingTransfer {
    #[serde(with = "serde_string")]
    pub tokens: BigUint,
    /// Not the address of the token wallet, but the address of its owner
    #[serde(with = "serde_address")]
    pub sender_address: MsgAddressInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenOutgoingTransfer {
    pub to: TransferRecipient,
    #[serde(with = "serde_string")]
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
        #[serde(rename_all = "snake_case", tag = "type", content = "address")]
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
    #[serde(with = "serde_string")]
    pub tokens: BigUint,
    #[serde(with = "serde_address")]
    pub callback_address: MsgAddressInt,
    /// ETH address or something else
    #[serde(with = "serde_cell")]
    pub callback_payload: ton_types::Cell,
}

#[derive(Clone, Debug, Serialize, Deserialize, Copy)]
#[serde(rename_all = "camelCase")]
pub struct EthEventDetails {
    pub status: EthEventStatus,
    pub required_confirmation_count: u16,
    pub required_rejection_count: u16,
    pub confirmation_count: u16,
    pub rejection_count: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthEventData {
    #[serde(with = "serde_address")]
    pub root_token_contract: MsgAddressInt,
    #[serde(with = "serde_string")]
    pub tokens: BigUint,
}

#[derive(Clone, Debug, Serialize, Deserialize, Copy)]
#[serde(rename_all = "camelCase")]
pub struct TonEventDetails {
    pub status: TonEventStatus,
    pub required_confirmation_count: u16,
    pub required_rejection_count: u16,
    pub confirmation_count: u16,
    pub rejection_count: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TonEventData {
    #[serde(with = "serde_address")]
    pub root_token_contract: MsgAddressInt,
    #[serde(with = "serde_string")]
    pub tokens: BigUint,
    /// ETH address
    pub to: String,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PollingMethod {
    /// Manual polling once a minute or by a click.
    /// Used when there are no pending transactions
    Manual,
    /// Block-walking for GQL or fast refresh for ADNL.
    /// Used when there are some pending transactions
    Reliable,
}

define_string_enum!(
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub enum ReliableBehavior {
        /// Used for transports which doesn't support getting blocks directly (ADNL)
        IntensivePolling,
        /// Used for transports which support getting blocks directly (GQL)
        BlockWalking,
    }
);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type", content = "data")]
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
    pub fn timestamp(&self, clock: &dyn Clock) -> u32 {
        match self {
            Self::Never => u32::MAX,
            Self::Timeout(timeout) => clock.now_sec_u64() as u32 + timeout,
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
    pub fn new(clock: &dyn Clock, expiration: Expiration) -> Self {
        Self {
            expiration,
            timestamp: expiration.timestamp(clock),
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

    pub fn refresh(&mut self, clock: &dyn Clock) -> bool {
        let old_timestamp = self.timestamp;
        self.timestamp = self.expiration.timestamp(clock);
        self.timestamp != old_timestamp
    }

    pub fn refresh_from_millis(&mut self, time: u64) -> bool {
        let old_timestamp = self.timestamp;

        self.timestamp = match self.expiration {
            Expiration::Never => u32::MAX,
            Expiration::Timeout(timeout) => (time / 1000) as u32 + timeout,
            Expiration::Timestamp(timestamp) => timestamp,
        };
        self.timestamp != old_timestamp
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Symbol {
    /// Short name, e.g. USDT, DAI, etc.
    pub name: String,

    /// Full name
    pub full_name: String,

    /// Fixed decimals count
    pub decimals: u8,

    /// Address of the root token contract
    #[serde(with = "serde_address")]
    pub root_token_contract: MsgAddressInt,
}

define_string_enum!(
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
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
#[serde(rename_all = "camelCase")]
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

    #[serde(with = "serde_string")]
    pub balance: BigUint,
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
    #[serde(with = "serde_string")]
    pub total_supply: BigUint,
    #[serde(with = "serde_uint256")]
    pub root_public_key: UInt256,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Copy)]
#[serde(rename_all = "camelCase")]
pub struct ContractState {
    /// Full account balance in nano TON
    #[serde(with = "serde_string")]
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingTransaction {
    /// External message hash
    #[serde(with = "serde_uint256")]
    pub message_hash: UInt256,
    /// Hash of the external message body. Used to identify message in executed transactions
    #[serde(with = "serde_uint256")]
    pub body_hash: UInt256,
    /// Incoming message source
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_optional_address"
    )]
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
#[serde(rename_all = "camelCase")]
pub struct TransactionsBatchInfo {
    /// The smallest lt in a group
    #[serde(with = "serde_string")]
    pub min_lt: u64,
    /// Maximum lt in a group
    #[serde(with = "serde_string")]
    pub max_lt: u64,
    /// Whether this batch was from the preload request
    pub batch_type: TransactionsBatchType,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransactionsBatchType {
    Old,
    New,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    /// Full transaction id
    pub id: TransactionId,
    /// Previous transaction id. `None` for last transaction
    #[serde(rename = "prevTransactionId")]
    pub prev_trans_id: Option<TransactionId>,
    /// Transaction unix timestamp
    pub created_at: u32,
    /// Whether transaction execution was unsuccessful
    pub aborted: bool,
    /// Compute phase result code. `None` if compute phase was skipped
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Action phase result code. `None` if action phase was skipped
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_code: Option<i32>,
    /// Account status before transaction execution
    pub orig_status: AccountStatus,
    /// Account status after transaction execution
    pub end_status: AccountStatus,
    /// Sum of fees from all execution stages
    #[serde(with = "serde_string")]
    pub total_fees: u64,
    /// Incoming message
    #[serde(rename = "inMessage")]
    pub in_msg: Message,
    /// Outgoing messages
    #[serde(rename = "outMessages")]
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

        let total_fees = compute_total_transaction_fees(&data, &desc) as u64;

        let in_msg = match data.in_msg.take() {
            Some(message) => message
                .read_struct()
                .map(Message::from)
                .map_err(|_| TransactionError::InvalidStructure)?,
            None => return Err(TransactionError::Unsupported),
        };

        let exit_code = match &desc.compute_ph {
            ton_block::TrComputePhase::Vm(vm) => Some(vm.exit_code),
            ton_block::TrComputePhase::Skipped(_) => None,
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
            exit_code,
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

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default)]
pub struct Message {
    /// Source message address, `None` for external messages
    pub src: Option<MsgAddressInt>,

    /// Destination message address, `None` for outbound messages
    pub dst: Option<MsgAddressInt>,

    /// Message value in nano TON
    pub value: u64,

    /// Whether this message will be bounced on unsuccessful execution.
    pub bounce: bool,

    /// Whether this message was bounced during unsuccessful execution.
    /// Only relevant for internal messages
    pub bounced: bool,

    /// Message body
    pub body: Option<MessageBody>,
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct MessageHelper {
            #[serde(default, with = "serde_optional_address")]
            src: Option<MsgAddressInt>,
            #[serde(default, with = "serde_optional_address")]
            dst: Option<MsgAddressInt>,
            #[serde(with = "serde_string")]
            value: u64,
            bounce: bool,
            bounced: bool,
            body: Option<String>,
        }

        let parsed = MessageHelper::deserialize(deserializer)?;
        let body = match parsed.body {
            Some(data) => {
                let data = base64::decode(&data).map_err(D::Error::custom)?;
                let data = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(data))
                    .map_err(D::Error::custom)?;
                let hash = data.repr_hash();
                Some(MessageBody { hash, data })
            }
            None => None,
        };

        Ok(Self {
            src: parsed.src,
            dst: parsed.dst,
            value: parsed.value,
            bounce: parsed.bounce,
            bounced: parsed.bounced,
            body,
        })
    }
}

impl Serialize for Message {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::Error;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct MessageHelper<'a> {
            #[serde(
                skip_serializing_if = "Option::is_none",
                with = "serde_optional_address"
            )]
            src: &'a Option<MsgAddressInt>,
            #[serde(
                skip_serializing_if = "Option::is_none",
                with = "serde_optional_address"
            )]
            dst: &'a Option<MsgAddressInt>,
            value: String,
            bounce: bool,
            bounced: bool,
            body: Option<String>,
            body_hash: Option<String>,
        }

        let (body, body_hash) = match &self.body {
            Some(body) => {
                let data = ton_types::serialize_toc(&body.data).map_err(S::Error::custom)?;
                (Some(base64::encode(data)), Some(body.hash.to_hex_string()))
            }
            None => (None, None),
        };

        MessageHelper {
            src: &self.src,
            dst: &self.dst,
            value: self.value.to_string(),
            bounce: self.bounce,
            bounced: self.bounced,
            body,
            body_hash,
        }
        .serialize(serializer)
    }
}

impl From<ton_block::Message> for Message {
    fn from(s: ton_block::Message) -> Self {
        let body = s.body().map(|body| {
            let data = body.into_cell();
            MessageBody {
                hash: data.repr_hash(),
                data,
            }
        });

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
    #[serde(with = "serde_cell")]
    pub data: ton_types::Cell,
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum MessageBodyError {
    #[error("Failed to serialize data")]
    FailedToSerialize,
    #[error("Failed to deserialize data")]
    FailedToDeserialize,
}

#[derive(thiserror::Error, Debug)]
pub(super) enum AccountSubscriptionError {
    #[error("Invalid message destination")]
    InvalidMessageDestination,
    #[error("Invalid message type")]
    InvalidMessageType,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MessageFlags {
    Normal,
    AllBalance,
    AllBalanceDeleteNetworkAccount,
}

impl TryFrom<u8> for MessageFlags {
    type Error = MessageFlagsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            3 => Ok(MessageFlags::Normal),
            131 => Ok(MessageFlags::AllBalance),
            160 => Ok(MessageFlags::AllBalanceDeleteNetworkAccount),
            _ => Err(MessageFlagsError::UnknownMessageFlags),
        }
    }
}

impl From<MessageFlags> for u8 {
    fn from(value: MessageFlags) -> u8 {
        match value {
            MessageFlags::Normal => 3,
            MessageFlags::AllBalance => 128 + 3,
            MessageFlags::AllBalanceDeleteNetworkAccount => 128 + 32,
        }
    }
}

impl Default for MessageFlags {
    fn default() -> Self {
        MessageFlags::Normal
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum MessageFlagsError {
    #[error("Unknown message flags combination")]
    UnknownMessageFlags,
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
