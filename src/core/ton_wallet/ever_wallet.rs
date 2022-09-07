use anyhow::Result;
use ed25519_dalek::PublicKey;
use std::borrow::Cow;
use ton_block::{GetRepresentationHash, MsgAddressInt, Serializable};
use ton_types::{BuilderData, IBitstring, UInt256};

use nekoton_abi::{BigUint128, BuildTokenValue, MessageBuilder};
use nekoton_utils::*;

use super::{Gift, TonWalletDetails, TransferAction};
use crate::core::models::Expiration;
use crate::core::utils::make_labs_unsigned_message;
use crate::crypto::UnsignedMessage;

pub fn prepare_deploy(
    clock: &dyn Clock,
    public_key: &PublicKey,
    workchain: i8,
    expiration: Expiration,
) -> Result<Box<dyn UnsignedMessage>> {
    let state_init = make_state_init(public_key)?;
    let hash = state_init.hash()?;

    let dst = MsgAddressInt::AddrStd(ton_block::MsgAddrStd::with_address(
        None,
        workchain,
        hash.into(),
    ));

    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst,
            ..Default::default()
        });
    message.set_state_init(state_init);

    let (function, input) =
        MessageBuilder::new(nekoton_contracts::wallets::ever_wallet::send_transaction_raw_0())
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
    current_state: &ton_block::AccountStuff,
    address: MsgAddressInt,
    gifts: Vec<Gift>,
    expiration: Expiration,
) -> Result<TransferAction> {
    use nekoton_contracts::wallets::ever_wallet;

    if gifts.len() > MAX_MESSAGES {
        return Err(EverWalletError::TooManyGifts.into());
    }

    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst: address,
            ..Default::default()
        });

    match &current_state.storage.state {
        ton_block::AccountState::AccountActive { .. } => {}
        ton_block::AccountState::AccountFrozen { .. } => {
            return Err(EverWalletError::AccountIsFrozen.into())
        }
        ton_block::AccountState::AccountUninit => {
            message.set_state_init(make_state_init(public_key)?);
        }
    };

    let mut gifts = gifts.into_iter();
    let (function, input) = match (gifts.next(), gifts.len()) {
        (Some(gift), 1) if gift.state_init.is_none() => {
            MessageBuilder::new(ever_wallet::send_transaction())
                .arg(gift.destination)
                .arg(BigUint128(gift.amount.into()))
                .arg(gift.bounce)
                .arg(gift.flags)
                .arg(gift.body.unwrap_or_default().into_cell())
                .build()
        }
        (gift, len) => {
            let function = match len {
                0 => ever_wallet::send_transaction_raw_0(),
                1 => ever_wallet::send_transaction_raw_1(),
                2 => ever_wallet::send_transaction_raw_2(),
                3 => ever_wallet::send_transaction_raw_3(),
                _ => ever_wallet::send_transaction_raw_4(),
            };

            let mut tokens = Vec::with_capacity(len * 2);
            for gift in gift.into_iter().chain(gifts) {
                let mut internal_message =
                    ton_block::Message::with_int_header(ton_block::InternalMessageHeader {
                        ihr_disabled: true,
                        bounce: gift.bounce,
                        dst: gift.destination,
                        value: gift.amount.into(),
                        ..Default::default()
                    });

                if let Some(body) = gift.body {
                    internal_message.set_body(body);
                }

                if let Some(state_init) = gift.state_init {
                    internal_message.set_state_init(state_init);
                }

                tokens.push(ton_abi::Token::new("flags", gift.flags.token_value()));
                tokens.push(ton_abi::Token::new(
                    "message",
                    internal_message.serialize()?.token_value(),
                ));
            }

            (function, tokens)
        }
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

pub const CODE_HASH: [u8; 32] = [
    0x3b, 0xa6, 0x52, 0x8a, 0xb2, 0x69, 0x4c, 0x11, 0x81, 0x80, 0xaa, 0x3b, 0xd1, 0x0d, 0xd1, 0x9f,
    0xf4, 0x00, 0xb9, 0x09, 0xab, 0x4d, 0xcf, 0x58, 0xfc, 0x69, 0x92, 0x5b, 0x2c, 0x7b, 0x12, 0xa6,
];

pub fn is_ever_wallet(code_hash: &UInt256) -> bool {
    code_hash.as_slice() == &CODE_HASH
}

pub fn compute_contract_address(public_key: &PublicKey, workchain_id: i8) -> MsgAddressInt {
    let hash = make_state_init(public_key)
        .and_then(|state| state.hash())
        .trust_me();
    MsgAddressInt::AddrStd(ton_block::MsgAddrStd::with_address(
        None,
        workchain_id,
        hash.into(),
    ))
}

pub fn make_state_init(public_key: &PublicKey) -> Result<ton_block::StateInit> {
    let mut data = BuilderData::new();
    data.append_raw(public_key.as_bytes(), 256)?.append_u64(0)?;
    let data = data.into_cell()?;

    Ok(ton_block::StateInit {
        code: Some(nekoton_contracts::wallets::code::ever_wallet()),
        data: Some(data),
        ..Default::default()
    })
}

pub static DETAILS: TonWalletDetails = TonWalletDetails {
    requires_separate_deploy: false,
    min_amount: 1, // 0.000000001 EVER
    max_messages: MAX_MESSAGES,
    supports_payload: true,
    supports_state_init: true,
    supports_multiple_owners: false,
    expiration_time: 0,
};

const MAX_MESSAGES: usize = 4;

#[derive(thiserror::Error, Debug)]
enum EverWalletError {
    #[error("Account is frozen")]
    AccountIsFrozen,
    #[error("Too many outgoing messages")]
    TooManyGifts,
}
