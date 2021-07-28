use std::borrow::Cow;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use ton_block::{GetRepresentationHash, MsgAddressInt};
use ton_types::{SliceData, UInt256};

use super::super::TransferAction;
use super::super::DEFAULT_WORKCHAIN;
use super::prepare_state_init;
use super::MultisigType;
use crate::contracts;
use crate::core::models::Expiration;
use crate::core::utils::*;
use crate::crypto::UnsignedMessage;
use crate::parser::abi::{BigUint128, MessageBuilder};
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
