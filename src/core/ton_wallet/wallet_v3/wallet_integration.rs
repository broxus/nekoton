use std::convert::TryFrom;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use ton_block::MsgAddressInt;
use ton_types::{BuilderData, SliceData, UInt256};

use super::super::TonWallet;
use super::super::TransferAction;
use super::super::DEFAULT_WORKCHAIN;
use super::{compute_contract_address, WALLET_ID};
use super::{Gift, InitData};
use crate::core::models::{Expiration, ExpireAt};
use crate::core::InternalMessage;
use crate::crypto::{SignedMessage, UnsignedMessage};
use crate::utils::*;

pub fn prepare_deploy(
    public_key: &PublicKey,
    expiration: Expiration,
) -> Result<Box<dyn UnsignedMessage>> {
    let init_data = InitData::from_key(public_key).with_wallet_id(WALLET_ID);
    let dst = compute_contract_address(public_key, DEFAULT_WORKCHAIN);
    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst,
            ..Default::default()
        });

    message.set_state_init(
        InitData::from_key(public_key)
            .with_wallet_id(WALLET_ID)
            .make_state_init()?,
    );

    let expire_at = ExpireAt::new(expiration);
    let (hash, payload) = init_data.make_transfer_payload(None, expire_at.timestamp)?;

    Ok(Box::new(UnsignedWalletV3Message {
        init_data,
        gift: None,
        payload,
        message,
        expire_at,
        hash,
    }))
}

#[derive(Clone)]
struct UnsignedWalletV3Deploy {
    message: ton_block::Message,
    expire_at: ExpireAt,
}

impl UnsignedMessage for UnsignedWalletV3Deploy {
    fn refresh_timeout(&mut self) {
        self.expire_at.refresh();
    }

    fn expire_at(&self) -> u32 {
        self.expire_at.timestamp
    }

    fn hash(&self) -> &[u8] {
        // return empty hash, because there is no message body
        &[0; 32]
    }

    fn sign(&self, _: &[u8; ed25519_dalek::SIGNATURE_LENGTH]) -> Result<SignedMessage> {
        Ok(SignedMessage {
            message: self.message.clone(),
            expire_at: self.expire_at(),
        })
    }
}

pub fn prepare_transfer(
    public_key: &PublicKey,
    current_state: &ton_block::AccountStuff,
    destination: MsgAddressInt,
    amount: u64,
    bounce: bool,
    body: Option<SliceData>,
    expiration: Expiration,
) -> Result<TransferAction> {
    let (init_data, with_state_init) = match &current_state.storage.state {
        ton_block::AccountState::AccountActive(active) => match &active.data {
            Some(data) => (InitData::try_from(data)?, false),
            None => return Err(WalletV3Error::InvalidInitData.into()),
        },
        ton_block::AccountState::AccountFrozen(_) => {
            return Err(WalletV3Error::AccountIsFrozen.into())
        }
        ton_block::AccountState::AccountUninit => (
            InitData::from_key(public_key).with_wallet_id(WALLET_ID),
            true,
        ),
    };

    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst: current_state.addr.clone(),
            ..Default::default()
        });

    if with_state_init {
        message.set_state_init(init_data.make_state_init()?);
    }

    let gift = Some(Gift {
        flags: 3,
        bounce,
        destination,
        amount,
        body,
        state_init: None,
    });

    let expire_at = ExpireAt::new(expiration);
    let (hash, payload) = init_data.make_transfer_payload(gift.clone(), expire_at.timestamp)?;

    Ok(TransferAction::Sign(Box::new(UnsignedWalletV3Message {
        init_data,
        gift,
        payload,
        hash,
        expire_at,
        message,
    })))
}

#[derive(Clone)]
struct UnsignedWalletV3Message {
    init_data: InitData,
    gift: Option<Gift>,
    payload: BuilderData,
    hash: UInt256,
    expire_at: ExpireAt,
    message: ton_block::Message,
}

impl UnsignedMessage for UnsignedWalletV3Message {
    fn refresh_timeout(&mut self) {
        if !self.expire_at.refresh() {
            return;
        }

        let (hash, payload) = self
            .init_data
            .make_transfer_payload(self.gift.clone(), self.expire_at())
            .trust_me();
        self.hash = hash;
        self.payload = payload;
    }

    fn expire_at(&self) -> u32 {
        self.expire_at.timestamp
    }

    fn hash(&self) -> &[u8] {
        self.hash.as_slice()
    }

    fn sign(&self, signature: &[u8; ed25519_dalek::SIGNATURE_LENGTH]) -> Result<SignedMessage> {
        let mut payload = self.payload.clone();
        payload
            .prepend_raw(signature, signature.len() * 8)
            .convert()?;

        let mut message = self.message.clone();
        message.set_body(payload.into());

        Ok(SignedMessage {
            message,
            expire_at: self.expire_at(),
        })
    }
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
enum WalletV3Error {
    #[error("Invalid init data")]
    InvalidInitData,
    #[error("Account is frozen")]
    AccountIsFrozen,
}
