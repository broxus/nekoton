use std::borrow::Cow;
use std::convert::TryFrom;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use ton_block::{Deserializable, GetRepresentationHash, MsgAddressInt, Serializable};
use ton_types::UInt256;

use nekoton_abi::*;
use nekoton_utils::*;

use super::{Gift, TonWalletDetails, TransferAction};
use crate::core::models::{Expiration, MessageFlags, MultisigPendingTransaction};
use crate::core::utils::*;
use crate::crypto::UnsignedMessage;

#[derive(Copy, Clone, Debug)]
pub struct DeployParams<'a> {
    pub owners: &'a [PublicKey],
    pub req_confirms: u8,
    pub expiration_time: Option<u32>,
}

impl<'a> DeployParams<'a> {
    pub fn single_custodian(pubkey: &'a PublicKey) -> Self {
        Self {
            owners: std::slice::from_ref(pubkey),
            req_confirms: 1,
            expiration_time: None,
        }
    }
}

pub fn prepare_deploy(
    clock: &dyn Clock,
    public_key: &PublicKey,
    multisig_type: MultisigType,
    workchain: i8,
    expiration: Expiration,
    params: DeployParams<'_>,
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

    let owners = params
        .owners
        .iter()
        .map(|public_key| UInt256::from(public_key.as_bytes()))
        .collect::<Vec<UInt256>>();

    let is_new_multisig = multisig_type == MultisigType::Multisig2;
    let function = if is_new_multisig {
        nekoton_contracts::wallets::multisig2::constructor()
    } else if params.expiration_time.is_none() {
        nekoton_contracts::wallets::multisig::constructor()
    } else {
        return Err(MultisigError::CustomExpirationTimeNotSupported.into());
    };

    let (function, input) = {
        let mut message = MessageBuilder::new(function)
            .arg(owners)
            .arg(params.req_confirms);
        if is_new_multisig {
            message = message.arg(params.expiration_time.unwrap_or(DEFAULT_LIFETIME));
        }
        message.build()
    };

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
    multisig_type: MultisigType,
    public_key: &PublicKey,
    address: MsgAddressInt,
    transaction_id: u64,
    expiration: Expiration,
) -> Result<Box<dyn UnsignedMessage>> {
    let message = ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
        dst: address,
        ..Default::default()
    });

    let function = if multisig_type == MultisigType::Multisig2 {
        nekoton_contracts::wallets::multisig2::confirm_transaction()
    } else {
        nekoton_contracts::wallets::multisig::confirm_transaction()
    };
    let (function, input) = MessageBuilder::new(function).arg(transaction_id).build();

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
    multisig_type: MultisigType,
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

    let is_new_multisig = multisig_type == MultisigType::Multisig2;

    let (function, input) = if has_multiple_owners || is_new_multisig && gift.state_init.is_some() {
        let all_balance = match MessageFlags::try_from(gift.flags) {
            Ok(MessageFlags::Normal) => false,
            Ok(MessageFlags::AllBalance) => true,
            _ => return Err(MultisigError::UnsupportedFlagsSet.into()),
        };

        let function = if is_new_multisig {
            nekoton_contracts::wallets::multisig2::submit_transaction()
        } else {
            nekoton_contracts::wallets::multisig::submit_transaction()
        };

        let message = MessageBuilder::new(function)
            .arg(gift.destination)
            .arg(BigUint128(gift.amount.into()))
            .arg(gift.bounce)
            .arg(all_balance)
            .arg(gift.body.unwrap_or_default().into_cell());

        if is_new_multisig {
            message
                .arg(
                    gift.state_init
                        .map(|state_init| state_init.serialize())
                        .transpose()?,
                )
                .build()
        } else {
            message.build()
        }
    } else {
        let function = if is_new_multisig {
            nekoton_contracts::wallets::multisig2::send_transaction()
        } else {
            nekoton_contracts::wallets::multisig::send_transaction()
        };
        MessageBuilder::new(function)
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
        Multisig2,
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
const MULTISIG2_HASH: [u8; 32] = [
    0x29, 0xb2, 0x47, 0x76, 0xb3, 0xdf, 0x6a, 0x05, 0xc5, 0xa1, 0xb8, 0xd8, 0xfd, 0x75, 0xcb, 0x72,
    0xa1, 0xd3, 0x3c, 0x0a, 0x44, 0x38, 0x53, 0x32, 0xa8, 0xbf, 0xc2, 0x72, 0x7f, 0xb6, 0x65, 0x90,
];

pub fn guess_multisig_type(code_hash: &UInt256) -> Option<MultisigType> {
    match *code_hash.as_slice() {
        SAFE_MULTISIG_WALLET_HASH => Some(MultisigType::SafeMultisigWallet),
        SAFE_MULTISIG_WALLET_24H_HASH => Some(MultisigType::SafeMultisigWallet24h),
        SETCODE_MULTISIG_WALLET_HASH => Some(MultisigType::SetcodeMultisigWallet),
        BRIDGE_MULTISIG_WALLET_HASH => Some(MultisigType::BridgeMultisigWallet),
        SETCODE_MULTISIG_WALLET_24H_HASH => Some(MultisigType::SetcodeMultisigWallet24h),
        SURF_WALLET_HASH => Some(MultisigType::SurfWallet),
        MULTISIG2_HASH => Some(MultisigType::Multisig2),
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
        min_amount: if multisig_type == MultisigType::Multisig2 {
            0
        } else {
            1000000 // 0.001 EVER
        },
        max_messages: 1,
        supports_payload: true,
        supports_state_init: multisig_type == MultisigType::Multisig2,
        supports_multiple_owners: true,
        expiration_time: match multisig_type {
            MultisigType::SafeMultisigWallet
            | MultisigType::SetcodeMultisigWallet
            | MultisigType::Multisig2 => 3600,
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
        MultisigType::Multisig2 => wallets::code::multisig2(),
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

pub fn get_expiration_time(
    clock: &dyn Clock,
    multisig_type: MultisigType,
    account_stuff: Cow<'_, ton_block::AccountStuff>,
) -> Result<u64> {
    #[derive(Copy, Clone, UnpackAbiPlain)]
    pub struct SetCodeMultisigParamsPrefix {
        #[abi(uint8, name = "maxQueuedTransactions")]
        pub _max_queued_transactions: u8,
        #[abi(uint8, name = "maxCustodianCount")]
        pub _max_custodian_count: u8,
        #[abi(uint64, name = "expirationTime")]
        pub expiration_time: u64,
    }

    let function = match multisig_type {
        MultisigType::Multisig2 => nekoton_contracts::wallets::multisig2::get_parameters(),
        MultisigType::SafeMultisigWallet
        | MultisigType::SafeMultisigWallet24h
        | MultisigType::BridgeMultisigWallet => {
            nekoton_contracts::wallets::multisig::safe_multisig::get_parameters()
        }
        MultisigType::SetcodeMultisigWallet
        | MultisigType::SetcodeMultisigWallet24h
        | MultisigType::SurfWallet => {
            nekoton_contracts::wallets::multisig::set_code_multisig::get_parameters()
        }
    };

    let output: SetCodeMultisigParamsPrefix =
        run_local(clock, function, account_stuff.into_owned())?.unpack()?;
    Ok(output.expiration_time)
}

pub fn get_custodians(
    clock: &dyn Clock,
    multisig_type: MultisigType,
    account_stuff: Cow<'_, ton_block::AccountStuff>,
) -> Result<Vec<UInt256>> {
    let function = if multisig_type == MultisigType::Multisig2 {
        nekoton_contracts::wallets::multisig2::get_custodians()
    } else {
        nekoton_contracts::wallets::multisig::get_custodians()
    };
    run_local(clock, function, account_stuff.into_owned())
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
        .collect::<Result<Vec<nekoton_contracts::wallets::multisig::MultisigCustodian>, _>>()?;

    custodians.sort_by(|a, b| a.index.cmp(&b.index));

    Ok(custodians.into_iter().map(|item| item.pubkey).collect())
}

pub fn find_pending_transaction(
    clock: &dyn Clock,
    multisig_type: MultisigType,
    account_stuff: Cow<'_, ton_block::AccountStuff>,
    pending_transaction_id: u64,
) -> Result<bool> {
    #[derive(Copy, Clone, UnpackAbi)]
    pub struct MultisigTransactionId {
        #[abi(uint64)]
        pub id: u64,
    }

    let function = if multisig_type == MultisigType::Multisig2 {
        nekoton_contracts::wallets::multisig2::get_transactions()
    } else {
        nekoton_contracts::wallets::multisig::get_transactions()
    };

    let tokens = run_local(clock, function, account_stuff.into_owned())?;

    let array = match tokens.into_unpacker().unpack_next() {
        Ok(ton_abi::TokenValue::Array(_, tokens)) => tokens,
        _ => return Err(UnpackerError::InvalidAbi.into()),
    };

    for item in array {
        let MultisigTransactionId { id } = item.unpack()?;
        if pending_transaction_id == id {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn get_pending_transactions(
    clock: &dyn Clock,
    multisig_type: MultisigType,
    account_stuff: Cow<'_, ton_block::AccountStuff>,
    custodians: &[UInt256],
) -> Result<Vec<MultisigPendingTransaction>> {
    let function = if multisig_type == MultisigType::Multisig2 {
        nekoton_contracts::wallets::multisig2::get_transactions()
    } else {
        nekoton_contracts::wallets::multisig::get_transactions()
    };
    run_local(clock, function, account_stuff.into_owned()).and_then(|tokens| {
        let array = match tokens.into_unpacker().unpack_next() {
            Ok(ton_abi::TokenValue::Array(_, tokens)) => tokens,
            _ => return Err(UnpackerError::InvalidAbi.into()),
        };

        let transactions = array
            .into_iter()
            .map(|item| Ok(extend_pending_transaction(item.unpack()?, custodians)))
            .collect::<UnpackerResult<Vec<MultisigPendingTransaction>>>()?;

        Ok(transactions)
    })
}

fn extend_pending_transaction(
    tx: nekoton_contracts::wallets::multisig::MultisigTransaction,
    custodians: &[UInt256],
) -> MultisigPendingTransaction {
    let confirmations = custodians
        .iter()
        .enumerate()
        .filter(|(i, _)| (0b1 << i) & tx.confirmation_mask != 0)
        .map(|(_, item)| *item)
        .collect::<Vec<UInt256>>();

    MultisigPendingTransaction {
        id: tx.id,
        confirmations,
        signs_required: tx.signs_required,
        signs_received: tx.signs_received,
        creator: tx.creator,
        index: tx.index,
        dest: tx.dest,
        value: tx.value.into(),
        send_flags: tx.send_flags,
        payload: tx.payload,
        bounce: tx.bounce,
    }
}

const DEFAULT_LIFETIME: u32 = 3600;

#[derive(thiserror::Error, Debug)]
enum MultisigError {
    #[error("Non-zero execution result code: {}", .0)]
    NonZeroResultCode(i32),
    #[error("Unsupported message flags set")]
    UnsupportedFlagsSet,
    #[error("Custom lifetime is not supported for this contract type")]
    CustomExpirationTimeNotSupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_address() {
        let key = PublicKey::from_bytes(
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
