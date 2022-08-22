use std::borrow::Cow;
use std::convert::TryFrom;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use num_bigint::BigUint;
use ton_block::{Deserializable, GetRepresentationHash, MsgAddressInt};
use ton_types::UInt256;

use nekoton_abi::*;
use nekoton_utils::*;

use super::{Gift, TonWalletDetails, TransferAction};
use crate::core::models::{Expiration, MessageFlags, MultisigPendingTransaction};
use crate::core::utils::*;
use crate::crypto::UnsignedMessage;

pub fn prepare_deploy(
    clock: &dyn Clock,
    public_key: &PublicKey,
    multisig_type: MultisigType,
    workchain: i8,
    expiration: Expiration,
    owners: &[PublicKey],
    req_confirms: u8,
) -> Result<Box<dyn UnsignedMessage>> {
    let state_init = prepare_state_init(public_key, multisig_type);
    let hash = state_init.hash().trust_me();

    let dst = MsgAddressInt::AddrStd(ton_block::MsgAddrStd {
        anycast: None,
        workchain_id: workchain,
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
        MessageBuilder::new(nekoton_contracts::wallets::multisig::constructor())
            .arg(owners)
            .arg(req_confirms) // reqConfirms
            .build();

    make_labs_unsigned_message(
        clock,
        message,
        expiration,
        public_key,
        Cow::Borrowed(function),
        input,
    )
}

pub fn prepare_confirm_transaction(
    clock: &dyn Clock,
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
        MessageBuilder::new(nekoton_contracts::wallets::multisig::confirm_transaction())
            .arg(transaction_id)
            .build();

    make_labs_unsigned_message(
        clock,
        message,
        expiration,
        public_key,
        Cow::Borrowed(function),
        input,
    )
}

pub fn prepare_transfer(
    clock: &dyn Clock,
    public_key: &PublicKey,
    has_multiple_owners: bool,
    address: MsgAddressInt,
    gift: Gift,
    expiration: Expiration,
) -> Result<TransferAction> {
    let message = ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
        dst: address,
        ..Default::default()
    });

    let (function, input) = if has_multiple_owners {
        let all_balance = match MessageFlags::try_from(gift.flags) {
            Ok(MessageFlags::Normal) => false,
            Ok(MessageFlags::AllBalance) => true,
            _ => return Err(MultisigError::UnsupportedFlagsSet.into()),
        };

        MessageBuilder::new(nekoton_contracts::wallets::multisig::submit_transaction())
            .arg(gift.destination)
            .arg(BigUint128(gift.amount.into()))
            .arg(gift.bounce)
            .arg(all_balance)
            .arg(gift.body.unwrap_or_default().into_cell())
            .build()
    } else {
        MessageBuilder::new(nekoton_contracts::wallets::multisig::send_transaction())
            .arg(gift.destination)
            .arg(BigUint128(gift.amount.into()))
            .arg(gift.bounce)
            .arg(gift.flags)
            .arg(gift.body.unwrap_or_default().into_cell())
            .build()
    };

    Ok(TransferAction::Sign(make_labs_unsigned_message(
        clock,
        message,
        expiration,
        public_key,
        Cow::Borrowed(function),
        input,
    )?))
}

define_string_enum!(
    #[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    pub enum MultisigType {
        SafeMultisigWallet,
        SafeMultisigWallet24h,
        SetcodeMultisigWallet,
        SetcodeMultisigWallet24h,
        BridgeMultisigWallet,
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
const SETCODE_MULTISIG_WALLET_24H_HASH: [u8; 32] = [
    0xa4, 0x91, 0x80, 0x4c, 0xa5, 0x5d, 0xd5, 0xb2, 0x8c, 0xff, 0xdf, 0xf4, 0x8c, 0xb3, 0x41, 0x42,
    0x93, 0x09, 0x99, 0x62, 0x1a, 0x54, 0xac, 0xee, 0x6b, 0xe8, 0x3c, 0x34, 0x20, 0x51, 0xd8, 0x84,
];
const BRIDGE_MULTISIG_WALLET_HASH: [u8; 32] = [
    0xf3, 0xa0, 0x7a, 0xe8, 0x4f, 0xc3, 0x43, 0x25, 0x9d, 0x7f, 0xa4, 0x84, 0x7b, 0x86, 0x33, 0x5b,
    0x3f, 0xdc, 0xfc, 0x8b, 0x31, 0xf1, 0xba, 0x4b, 0x7a, 0x94, 0x99, 0xd5, 0x53, 0x0f, 0x0b, 0x18,
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
        BRIDGE_MULTISIG_WALLET_HASH => Some(MultisigType::BridgeMultisigWallet),
        SETCODE_MULTISIG_WALLET_24H_HASH => Some(MultisigType::SetcodeMultisigWallet24h),
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
        max_messages: 1,
        supports_payload: true,
        supports_state_init: false,
        supports_multiple_owners: true,
        expiration_time: match multisig_type {
            MultisigType::SafeMultisigWallet | MultisigType::SetcodeMultisigWallet => 3600,
            MultisigType::SurfWallet => 3601,
            MultisigType::SafeMultisigWallet24h
            | MultisigType::SetcodeMultisigWallet24h
            | MultisigType::BridgeMultisigWallet => 86400,
        },
    }
}

fn prepare_state_init(public_key: &PublicKey, multisig_type: MultisigType) -> ton_block::StateInit {
    use nekoton_contracts::wallets;

    let mut code = match multisig_type {
        MultisigType::SafeMultisigWallet => wallets::code::safe_multisig_wallet(),
        MultisigType::SafeMultisigWallet24h => wallets::code::safe_multisig_wallet_24h(),
        MultisigType::SetcodeMultisigWallet => wallets::code::setcode_multisig_wallet(),
        MultisigType::SetcodeMultisigWallet24h => wallets::code::setcode_multisig_wallet_24h(),
        MultisigType::BridgeMultisigWallet => wallets::code::bridge_multisig_wallet(),
        MultisigType::SurfWallet => wallets::code::surf_wallet(),
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
    clock: &dyn Clock,
    function: &ton_abi::Function,
    account_stuff: ton_block::AccountStuff,
) -> Result<Vec<ton_abi::Token>> {
    let ExecutionOutput {
        tokens,
        result_code,
    } = function.run_local(clock, account_stuff, &[])?;
    tokens.ok_or_else(|| MultisigError::NonZeroResultCode(result_code).into())
}

pub fn get_custodians(
    clock: &dyn Clock,
    account_stuff: Cow<'_, ton_block::AccountStuff>,
) -> Result<Vec<UInt256>> {
    run_local(
        clock,
        nekoton_contracts::wallets::multisig::get_custodians(),
        account_stuff.into_owned(),
    )
    .and_then(parse_multisig_contract_custodians)
}

fn parse_multisig_contract_custodians(tokens: Vec<ton_abi::Token>) -> Result<Vec<UInt256>> {
    let array = match tokens.into_unpacker().unpack_next() {
        Ok(ton_abi::TokenValue::Array(_, tokens)) => tokens,
        _ => return Err(UnpackerError::InvalidAbi.into()),
    };

    let mut custodians = array
        .into_iter()
        .map(|item| item.unpack())
        .collect::<Result<Vec<TonWalletCustodian>, _>>()?;

    custodians.sort_by(|a, b| a.index.cmp(&b.index));

    Ok(custodians.into_iter().map(|item| item.pubkey).collect())
}

pub fn find_pending_transaction(
    clock: &dyn Clock,
    account_stuff: Cow<'_, ton_block::AccountStuff>,
    pending_transaction_id: u64,
) -> Result<bool> {
    let tokens = run_local(
        clock,
        nekoton_contracts::wallets::multisig::get_transactions(),
        account_stuff.into_owned(),
    )?;

    let array = match tokens.into_unpacker().unpack_next() {
        Ok(ton_abi::TokenValue::Array(_, tokens)) => tokens,
        _ => return Err(UnpackerError::InvalidAbi.into()),
    };

    let transactions = array
        .into_iter()
        .map(|item| {
            let transaction: PendingTransaction = item.unpack()?;
            Ok(transaction)
        })
        .collect::<UnpackerResult<Vec<PendingTransaction>>>()?;

    for transaction in transactions {
        if pending_transaction_id == transaction.id {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn get_pending_transaction(
    clock: &dyn Clock,
    account_stuff: Cow<'_, ton_block::AccountStuff>,
    custodians: &[UInt256],
) -> Result<Vec<MultisigPendingTransaction>> {
    run_local(
        clock,
        nekoton_contracts::wallets::multisig::get_transactions(),
        account_stuff.into_owned(),
    )
    .and_then(|tokens| parse_multisig_contract_pending_transactions(tokens, custodians))
}

fn parse_multisig_contract_pending_transactions(
    tokens: Vec<ton_abi::Token>,
    custodians: &[UInt256],
) -> Result<Vec<MultisigPendingTransaction>> {
    let array = match tokens.into_unpacker().unpack_next() {
        Ok(ton_abi::TokenValue::Array(_, tokens)) => tokens,
        _ => return Err(UnpackerError::InvalidAbi.into()),
    };

    let transactions = array
        .into_iter()
        .map(|item| {
            let transaction: PendingTransaction = item.unpack()?;
            Ok(transaction.with_custodians(custodians))
        })
        .collect::<UnpackerResult<Vec<MultisigPendingTransaction>>>()?;

    Ok(transactions)
}

#[derive(thiserror::Error, Debug)]
enum MultisigError {
    #[error("Non-zero execution result code: {}", .0)]
    NonZeroResultCode(i32),
    #[error("Unsupported message flags set")]
    UnsupportedFlagsSet,
}

#[derive(UnpackAbi)]
struct TonWalletCustodian {
    #[abi(uint8)]
    index: u8,
    #[abi(with = "uint256_bytes")]
    pubkey: UInt256,
}

#[derive(UnpackAbi)]
struct PendingTransaction {
    #[abi(uint64)]
    id: u64,
    #[abi(uint32, name = "confirmationsMask")]
    confirmations_mask: u32,
    #[abi(uint8, name = "signsRequired")]
    signs_required: u8,
    #[abi(uint8, name = "signsReceived")]
    signs_received: u8,
    #[abi(with = "uint256_bytes")]
    creator: UInt256,
    #[abi(uint8)]
    index: u8,
    #[abi(address)]
    dest: MsgAddressInt,
    #[abi(with = "uint128_number")]
    value: BigUint,
    #[abi(uint16, name = "sendFlags")]
    send_flags: u16,
    #[abi(cell)]
    payload: ton_types::Cell,
    #[abi(bool)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_address() {
        let key = ed25519_dalek::PublicKey::from_bytes(
            &hex::decode("5ace46d93d8f3932499df9f2bc7ef787385e16965e7797258948febd186de7f6")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(
            compute_contract_address(&key, MultisigType::SetcodeMultisigWallet24h, 0).to_string(),
            "0:3de70f9212154344a3158768b3fed731fc865ca15948b0d6d0d34daf4c6a7a0a"
        );
    }
}
