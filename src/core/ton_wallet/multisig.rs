use std::borrow::Cow;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use num_bigint::BigUint;
use ton_block::{Deserializable, GetRepresentationHash, MsgAddressInt};
use ton_types::{SliceData, UInt256};

use super::utils::*;
use super::{TonWalletDetails, TransferAction, DEFAULT_WORKCHAIN};
use crate::contracts;
use crate::core::models::{Expiration, GenTimings, LastTransactionId, MultisigPendingTransaction};
use crate::crypto::UnsignedMessage;
use crate::helpers::abi::{self, BigUint128, FunctionExt, IntoParser, MessageBuilder, ParseToken};
use crate::utils::*;

pub fn prepare_deploy(
    public_key: &PublicKey,
    multisig_type: MultisigType,
    expiration: Expiration,
    owners: &[PublicKey],
    req_confirms: u8,
) -> Result<Box<dyn UnsignedMessage>> {
    let state_init = prepare_state_init(public_key, multisig_type);
    let hash = state_init.hash().trust_me();

    let dst = MsgAddressInt::AddrStd(ton_block::MsgAddrStd {
        anycast: None,
        workchain_id: DEFAULT_WORKCHAIN,
        address: hash.into(),
    });

    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst,
            ..Default::default()
        });

    message.set_state_init(state_init);

    let owners = owners
        .iter()
        .map(|public_key| UInt256::from(public_key.as_bytes()))
        .collect::<Vec<UInt256>>();

    let (function, input) =
        MessageBuilder::new(contracts::abi::safe_multisig_wallet(), "constructor")
            .trust_me()
            .arg(owners)
            .arg(req_confirms) // reqConfirms
            .build();

    make_labs_unsigned_message(
        message,
        expiration,
        public_key,
        Cow::Borrowed(function),
        input,
    )
}

pub fn prepare_confirm_transaction(
    public_key: &PublicKey,
    address: MsgAddressInt,
    transaction_id: u64,
    expiration: Expiration,
) -> Result<Box<dyn UnsignedMessage>> {
    let message = ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
        dst: address,
        ..Default::default()
    });

    let (function, input) =
        MessageBuilder::new(contracts::abi::safe_multisig_wallet(), "confirmTransaction")
            .trust_me()
            .arg(transaction_id)
            .build();

    make_labs_unsigned_message(
        message,
        expiration,
        public_key,
        Cow::Borrowed(function),
        input,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_transfer(
    public_key: &PublicKey,
    has_multiple_owners: bool,
    address: MsgAddressInt,
    destination: MsgAddressInt,
    amount: u64,
    bounce: bool,
    body: Option<SliceData>,
    expiration: Expiration,
) -> Result<TransferAction> {
    let message = ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
        dst: address,
        ..Default::default()
    });

    let (function, input) = if has_multiple_owners {
        MessageBuilder::new(contracts::abi::safe_multisig_wallet(), "submitTransaction")
            .trust_me()
            .arg(destination)
            .arg(BigUint128(amount.into()))
            .arg(bounce)
            .arg(false) // allBalance
            .arg(body.unwrap_or_default().into_cell())
            .build()
    } else {
        MessageBuilder::new(contracts::abi::safe_multisig_wallet(), "sendTransaction")
            .trust_me()
            .arg(destination)
            .arg(BigUint128(amount.into()))
            .arg(bounce)
            .arg(3u8) // flags
            .arg(body.unwrap_or_default().into_cell())
            .build()
    };

    Ok(TransferAction::Sign(make_labs_unsigned_message(
        message,
        expiration,
        public_key,
        Cow::Borrowed(function),
        input,
    )?))
}

crate::define_string_enum!(
    pub enum MultisigType {
        SafeMultisigWallet,
        SafeMultisigWallet24h,
        SetcodeMultisigWallet,
        SurfWallet,
    }
);

const SAFE_MULTISIG_WALLET_HASH: [u8; 32] = [
    0x80, 0xd6, 0xc4, 0x7c, 0x4a, 0x25, 0x54, 0x3c, 0x9b, 0x39, 0x7b, 0x71, 0x71, 0x6f, 0x3f, 0xae,
    0x1e, 0x2c, 0x5d, 0x24, 0x71, 0x74, 0xc5, 0x2e, 0x2c, 0x19, 0xbd, 0x89, 0x64, 0x42, 0xb1, 0x05,
];
const SAFE_MULTISIG_WALLET_24H_HASH: [u8; 32] = [
    0x7d, 0x09, 0x96, 0x94, 0x34, 0x06, 0xf7, 0xd6, 0x2a, 0x4f, 0xf2, 0x91, 0xb1, 0x22, 0x8b, 0xf0,
    0x6e, 0xbd, 0x3e, 0x04, 0x8b, 0x58, 0x43, 0x6c, 0x5b, 0x70, 0xfb, 0x77, 0xff, 0x8b, 0x4b, 0xf2,
];
const SETCODE_MULTISIG_WALLET_HASH: [u8; 32] = [
    0xe2, 0xb6, 0x0b, 0x6b, 0x60, 0x2c, 0x10, 0xce, 0xd7, 0xea, 0x8e, 0xde, 0x4b, 0xdf, 0x96, 0x34,
    0x2c, 0x97, 0x57, 0x0a, 0x37, 0x98, 0x06, 0x6f, 0x3f, 0xb5, 0x0a, 0x4b, 0x2b, 0x27, 0xa2, 0x08,
];
const SURF_WALLET_HASH: [u8; 32] = [
    0x20, 0x7d, 0xc5, 0x60, 0xc5, 0x95, 0x6d, 0xe1, 0xa2, 0xc1, 0x47, 0x93, 0x56, 0xf8, 0xf3, 0xee,
    0x70, 0xa5, 0x97, 0x67, 0xdb, 0x2b, 0xf4, 0x78, 0x8b, 0x1d, 0x61, 0xad, 0x42, 0xcd, 0xad, 0x82,
];

pub fn guess_multisig_type(code_hash: &UInt256) -> Option<MultisigType> {
    match *code_hash.as_slice() {
        SAFE_MULTISIG_WALLET_HASH => Some(MultisigType::SafeMultisigWallet),
        SAFE_MULTISIG_WALLET_24H_HASH => Some(MultisigType::SafeMultisigWallet24h),
        SETCODE_MULTISIG_WALLET_HASH => Some(MultisigType::SetcodeMultisigWallet),
        SURF_WALLET_HASH => Some(MultisigType::SurfWallet),
        _ => None,
    }
}

pub fn compute_contract_address(
    public_key: &PublicKey,
    multisig_type: MultisigType,
    workchain_id: i8,
) -> MsgAddressInt {
    let state_init = prepare_state_init(public_key, multisig_type);
    let hash = state_init.hash().trust_me();

    MsgAddressInt::AddrStd(ton_block::MsgAddrStd {
        anycast: None,
        workchain_id,
        address: hash.into(),
    })
}

pub fn ton_wallet_details(multisig_type: MultisigType) -> TonWalletDetails {
    TonWalletDetails {
        requires_separate_deploy: true,
        min_amount: 1000000, // 0.001 TON
        supports_payload: true,
        supports_multiple_owners: true,
        expiration_time: match multisig_type {
            MultisigType::SafeMultisigWallet | MultisigType::SetcodeMultisigWallet => 3600,
            MultisigType::SurfWallet => 3601,
            MultisigType::SafeMultisigWallet24h => 86400,
        },
    }
}

fn prepare_state_init(public_key: &PublicKey, multisig_type: MultisigType) -> ton_block::StateInit {
    let mut code = match multisig_type {
        MultisigType::SafeMultisigWallet => contracts::code::safe_multisig_wallet(),
        MultisigType::SafeMultisigWallet24h => contracts::code::safe_multisig_wallet_24h(),
        MultisigType::SetcodeMultisigWallet => contracts::code::setcode_multisig_wallet(),
        MultisigType::SurfWallet => contracts::code::surf_wallet(),
    }
    .into();

    let mut state_init = ton_block::StateInit::construct_from(&mut code).trust_me();

    let new_data = ton_abi::Contract::insert_pubkey(
        state_init.data.clone().unwrap_or_default().into(),
        public_key.as_bytes(),
    )
    .trust_me();
    state_init.set_data(new_data.into_cell());

    state_init
}

fn run_local(
    multisig_type: MultisigType,
    contract_method: &str,
    account_stuff: ton_block::AccountStuff,
    gen_timings: GenTimings,
    last_transaction_id: &LastTransactionId,
) -> Result<Vec<ton_abi::Token>> {
    let function: &ton_abi::Function = match multisig_type {
        MultisigType::SafeMultisigWallet | MultisigType::SafeMultisigWallet24h => {
            contracts::abi::safe_multisig_wallet()
        }
        MultisigType::SetcodeMultisigWallet | MultisigType::SurfWallet => {
            contracts::abi::setcode_multisig_wallet()
        }
    }
    .function(contract_method)
    .map_err(|err| err.compat())?;

    let input = Vec::with_capacity(function.inputs.len());
    function
        .run_local(account_stuff, gen_timings, last_transaction_id, &input)?
        .tokens
        .ok_or_else(|| MultisigError::NonZeroResultCode.into())
}

pub fn get_custodians(
    multisig_type: MultisigType,
    account_stuff: Cow<'_, ton_block::AccountStuff>,
    gen_timings: GenTimings,
    last_transaction_id: &LastTransactionId,
) -> Result<Vec<UInt256>> {
    run_local(
        multisig_type,
        "getCustodians",
        account_stuff.into_owned(),
        gen_timings,
        last_transaction_id,
    )
    .and_then(parse_multisig_contract_custodians)
}

fn parse_multisig_contract_custodians(tokens: Vec<ton_abi::Token>) -> Result<Vec<UInt256>> {
    let array = match tokens.into_parser().parse_next() {
        Ok(ton_abi::TokenValue::Array(tokens)) => tokens,
        _ => return Err(abi::ParserError::InvalidAbi.into()),
    };

    let mut custodians = array
        .into_iter()
        .map(|item| item.try_parse())
        .collect::<Result<Vec<TonWalletCustodian>, _>>()?;

    custodians.sort_by(|a, b| a.index.cmp(&b.index));

    Ok(custodians.into_iter().map(|item| item.pubkey).collect())
}

pub fn find_pending_transaction(
    multisig_type: MultisigType,
    account_stuff: Cow<'_, ton_block::AccountStuff>,
    gen_timings: GenTimings,
    last_transaction_id: &LastTransactionId,
    pending_transaction_id: u64,
) -> Result<bool> {
    let tokens = run_local(
        multisig_type,
        "getTransactions",
        account_stuff.into_owned(),
        gen_timings,
        last_transaction_id,
    )?;

    let array = match tokens.into_parser().parse_next() {
        Ok(ton_abi::TokenValue::Array(tokens)) => tokens,
        _ => return Err(abi::ParserError::InvalidAbi.into()),
    };

    for tokens in array {
        let mut tokens = match tokens {
            ton_abi::TokenValue::Tuple(tokens) => tokens.into_parser(),
            _ => return Err(abi::ParserError::InvalidAbi.into()),
        };

        let id: u64 = tokens.parse_next()?;
        if pending_transaction_id == id {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn get_pending_transaction(
    multisig_type: MultisigType,
    account_stuff: Cow<'_, ton_block::AccountStuff>,
    gen_timings: GenTimings,
    last_transaction_id: &LastTransactionId,
    custodians: &[UInt256],
) -> Result<Vec<MultisigPendingTransaction>> {
    run_local(
        multisig_type,
        "getTransactions",
        account_stuff.into_owned(),
        gen_timings,
        last_transaction_id,
    )
    .and_then(|tokens| parse_multisig_contract_pending_transactions(tokens, custodians))
}

fn parse_multisig_contract_pending_transactions(
    tokens: Vec<ton_abi::Token>,
    custodians: &[UInt256],
) -> Result<Vec<MultisigPendingTransaction>> {
    let array = match tokens.into_parser().parse_next() {
        Ok(ton_abi::TokenValue::Array(tokens)) => tokens,
        _ => return Err(abi::ParserError::InvalidAbi.into()),
    };

    let transactions = array
        .into_iter()
        .map(|item| {
            let transaction: PendingTransaction = item.try_parse()?;
            Ok(transaction.with_custodians(custodians))
        })
        .collect::<abi::ContractResult<Vec<MultisigPendingTransaction>>>()?;

    Ok(transactions)
}

#[derive(thiserror::Error, Debug)]
enum MultisigError {
    #[error("Non-zero execution result code")]
    NonZeroResultCode,
}

struct TonWalletCustodian {
    index: u8,
    pubkey: UInt256,
}

impl ParseToken<TonWalletCustodian> for ton_abi::TokenValue {
    fn try_parse(self) -> abi::ContractResult<TonWalletCustodian> {
        let mut tokens = match self {
            ton_abi::TokenValue::Tuple(tokens) => tokens.into_parser(),
            _ => return Err(abi::ParserError::InvalidAbi),
        };
        Ok(TonWalletCustodian {
            index: tokens.parse_next()?,
            pubkey: tokens.parse_next()?,
        })
    }
}

impl ParseToken<PendingTransaction> for ton_abi::TokenValue {
    fn try_parse(self) -> abi::ContractResult<PendingTransaction> {
        let mut tokens = match self {
            ton_abi::TokenValue::Tuple(tokens) => tokens.into_parser(),
            _ => return Err(abi::ParserError::InvalidAbi),
        };

        Ok(PendingTransaction {
            id: tokens.parse_next()?,
            confirmations_mask: tokens.parse_next()?,
            signs_required: tokens.parse_next()?,
            signs_received: tokens.parse_next()?,
            creator: tokens.parse_next()?,
            index: tokens.parse_next()?,
            dest: tokens.parse_next()?,
            value: tokens.parse_next()?,
            send_flags: tokens.parse_next()?,
            payload: tokens.parse_next()?,
            bounce: tokens.parse_next()?,
        })
    }
}

struct PendingTransaction {
    id: u64,
    confirmations_mask: u32,
    signs_required: u8,
    signs_received: u8,
    creator: UInt256,
    index: u8,
    dest: MsgAddressInt,
    value: BigUint,
    send_flags: u16,
    payload: ton_types::Cell,
    bounce: bool,
}

impl PendingTransaction {
    fn with_custodians(self, custodians: &[UInt256]) -> MultisigPendingTransaction {
        let confirmations = custodians
            .iter()
            .enumerate()
            .filter(|(i, _)| (0b1 << i) & self.confirmations_mask != 0)
            .map(|(_, item)| *item)
            .collect::<Vec<UInt256>>();

        MultisigPendingTransaction {
            id: self.id,
            confirmations,
            signs_required: self.signs_required,
            signs_received: self.signs_received,
            creator: self.creator,
            index: self.index,
            dest: self.dest,
            value: self.value,
            send_flags: self.send_flags,
            payload: self.payload,
            bounce: self.bounce,
        }
    }
}
