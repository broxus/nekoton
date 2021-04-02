use std::convert::TryFrom;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use ton_block::{MsgAddrStd, MsgAddressInt, Serializable};
use ton_types::{BuilderData, Cell, IBitstring, SliceData, UInt256};

use super::{TransferAction, DEFAULT_WORKCHAIN};
use crate::contracts;
use crate::storage::keystore::{SignedMessage, UnsignedMessage};
use crate::utils::*;

pub fn prepare_deploy(public_key: &PublicKey, expire_at: u32) -> Result<Box<dyn UnsignedMessage>> {
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

    Ok(Box::new(UnsignedWalletV3Deploy { message, expire_at }))
}

#[derive(Clone)]
struct UnsignedWalletV3Deploy {
    message: ton_block::Message,
    expire_at: u32,
}

impl UnsignedMessage for UnsignedWalletV3Deploy {
    fn hash(&self) -> &[u8] {
        &[]
    }

    fn sign(&self, _: &[u8; ed25519_dalek::SIGNATURE_LENGTH]) -> Result<SignedMessage> {
        Ok(SignedMessage {
            message: self.message.clone(),
            expire_at: self.expire_at,
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
    expire_at: u32,
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

    let (hash, payload) = init_data.make_transfer_payload(
        Gift {
            flags: 3,
            bounce,
            destination,
            amount,
            body,
            state_init: None,
        },
        expire_at,
    )?;

    Ok(TransferAction::Sign(Box::new(UnsignedWalletV3Message {
        hash,
        payload,
        expire_at,
        message,
    })))
}

#[derive(Clone)]
struct UnsignedWalletV3Message {
    hash: UInt256,
    payload: BuilderData,
    expire_at: u32,
    message: ton_block::Message,
}

impl UnsignedMessage for UnsignedWalletV3Message {
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
            expire_at: self.expire_at,
        })
    }
}

pub fn compute_contract_address(public_key: &PublicKey, workchain_id: i8) -> MsgAddressInt {
    InitData::from_key(public_key)
        .with_wallet_id(WALLET_ID)
        .compute_addr(workchain_id)
        .trust_me()
}

/// WalletV3 init data
pub struct InitData {
    pub seqno: u32,
    pub wallet_id: u32,
    pub public_key: UInt256,
}

impl InitData {
    pub fn from_key(key: &PublicKey) -> Self {
        Self {
            seqno: 0,
            wallet_id: 0,
            public_key: key.as_bytes().into(),
        }
    }

    pub fn with_wallet_id(mut self, id: u32) -> Self {
        self.wallet_id = id;
        self
    }

    pub fn compute_addr(&self, workchain_id: i8) -> Result<MsgAddressInt> {
        let init_state = self.make_state_init()?.serialize().convert()?;
        let hash = init_state.repr_hash();
        Ok(MsgAddressInt::AddrStd(MsgAddrStd {
            anycast: None,
            workchain_id,
            address: hash.into(),
        }))
    }

    pub fn make_state_init(&self) -> Result<ton_block::StateInit> {
        Ok(ton_block::StateInit {
            code: Some(contracts::code::wallet_v3()),
            data: Some(self.serialize()?),
            ..Default::default()
        })
    }

    pub fn serialize(&self) -> Result<Cell> {
        let mut data = BuilderData::new();
        data.append_u32(self.seqno)
            .convert()?
            .append_u32(self.wallet_id)
            .convert()?
            .append_raw(self.public_key.as_slice(), 256)
            .convert()?;
        data.into_cell().convert()
    }

    pub fn make_transfer_payload(
        &self,
        gift: Gift,
        expire_at: u32,
    ) -> Result<(UInt256, BuilderData)> {
        let mut payload = BuilderData::new();

        // insert prefix
        payload
            .append_u32(self.wallet_id)
            .convert()?
            .append_u32(expire_at)
            .convert()?
            .append_u32(self.seqno)
            .convert()?;

        // create internal message
        let mut internal_message =
            ton_block::Message::with_int_header(ton_block::InternalMessageHeader {
                ihr_disabled: true,
                bounce: gift.bounce,
                dst: gift.destination.clone(),
                value: gift.amount.into(),
                ..Default::default()
            });

        if let Some(body) = gift.body {
            internal_message.set_body(body);
        }

        if let Some(state_init) = gift.state_init {
            internal_message.set_state_init(state_init);
        }

        // append it to the body
        payload
            .append_u8(gift.flags)
            .convert()?
            .append_reference_cell(internal_message.serialize().convert()?);

        let hash = payload.clone().into_cell().convert()?.repr_hash();

        Ok((hash, payload))
    }
}

impl TryFrom<&Cell> for InitData {
    type Error = anyhow::Error;

    fn try_from(data: &Cell) -> Result<Self, Self::Error> {
        let mut cs = SliceData::from(data);
        Ok(Self {
            seqno: cs.get_next_u32().convert()?,
            wallet_id: cs.get_next_u32().convert()?,
            public_key: UInt256::from(cs.get_next_bytes(32).convert()?),
        })
    }
}

/// WalletV3 transfer info
pub struct Gift {
    pub flags: u8,
    pub bounce: bool,
    pub destination: MsgAddressInt,
    pub amount: u64,
    pub body: Option<SliceData>,
    pub state_init: Option<ton_block::StateInit>,
}

const WALLET_ID: u32 = 0x4BA92D8A;

#[derive(thiserror::Error, Debug)]
enum WalletV3Error {
    #[error("Invalid init data")]
    InvalidInitData,
    #[error("Account is frozen")]
    AccountIsFrozen,
}
