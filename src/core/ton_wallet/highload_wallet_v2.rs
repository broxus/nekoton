use std::convert::TryFrom;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use ton_block::{MsgAddrStd, MsgAddressInt, Serializable};
use ton_types::{BuilderData, Cell, IBitstring, SliceData, UInt256};

use nekoton_utils::*;

use super::{TonWalletDetails, TransferAction};
use crate::core::models::{Expiration, ExpireAt};
use crate::crypto::{SignedMessage, UnsignedMessage};

pub fn prepare_deploy(
    clock: &dyn Clock,
    public_key: &PublicKey,
    workchain: i8,
    expiration: Expiration,
) -> Result<Box<dyn UnsignedMessage>> {
    let init_data = InitData::from_key(public_key).with_wallet_id(WALLET_ID);
    let dst = compute_contract_address(public_key, workchain);
    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst,
            ..Default::default()
        });

    message.set_state_init(init_data.make_state_init()?);

    let expire_at = ExpireAt::new(clock, expiration);
    let (hash, payload) = init_data.make_deploy_payload(expire_at.timestamp)?;

    Ok(Box::new(UnsignedHighloadWalletV2Message {
        init_data,
        gifts: None,
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
    fn refresh_timeout(&mut self, clock: &dyn Clock) {
        self.expire_at.refresh(clock);
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
    clock: &dyn Clock,
    public_key: &PublicKey,
    current_state: &ton_block::AccountStuff,
    gifts: Vec<Gift>,
    expiration: Expiration,
) -> Result<TransferAction> {
    let (init_data, with_state_init) = match &current_state.storage.state {
        ton_block::AccountState::AccountActive { state_init, .. } => match &state_init.data {
            Some(data) => (InitData::try_from(data)?, false),
            None => return Err(HighloadWalletV2Error::InvalidInitData.into()),
        },
        ton_block::AccountState::AccountFrozen { .. } => {
            return Err(HighloadWalletV2Error::AccountIsFrozen.into())
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

    let expire_at = ExpireAt::new(clock, expiration);
    let (hash, payload) = init_data.make_transfer_payload(&gifts, expire_at.timestamp)?;

    Ok(TransferAction::Sign(Box::new(
        UnsignedHighloadWalletV2Message {
            init_data,
            gifts: Some(gifts),
            payload,
            hash,
            expire_at,
            message,
        },
    )))
}

#[derive(Clone)]
struct UnsignedHighloadWalletV2Message {
    init_data: InitData,
    gifts: Option<Vec<Gift>>,
    payload: BuilderData,
    hash: UInt256,
    expire_at: ExpireAt,
    message: ton_block::Message,
}

impl UnsignedMessage for UnsignedHighloadWalletV2Message {
    fn refresh_timeout(&mut self, clock: &dyn Clock) {
        if !self.expire_at.refresh(clock) {
            return;
        }

        let expire_at = self.expire_at();

        let (hash, payload) = match &self.gifts {
            Some(gifts) => self.init_data.make_transfer_payload(gifts, expire_at),
            None => self.init_data.make_deploy_payload(expire_at),
        }
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
        payload.prepend_raw(signature, signature.len() * 8)?;

        let mut message = self.message.clone();
        message.set_body(payload.into());

        Ok(SignedMessage {
            message,
            expire_at: self.expire_at(),
        })
    }
}

const HIGHLOAD_WALLET_V2_HASH: [u8; 32] = [
    0x0b, 0x3a, 0x88, 0x7a, 0xea, 0xcd, 0x2a, 0x7d, 0x40, 0xbb, 0x55, 0x50, 0xbc, 0x92, 0x53, 0x15,
    0x6a, 0x02, 0x90, 0x65, 0xae, 0xfb, 0x6d, 0x6b, 0x58, 0x37, 0x35, 0xd5, 0x8d, 0xa9, 0xd5, 0xbe,
];

pub fn is_highload_wallet_v2(code_hash: &UInt256) -> bool {
    code_hash.as_slice() == &HIGHLOAD_WALLET_V2_HASH
}

pub fn compute_contract_address(public_key: &PublicKey, workchain_id: i8) -> MsgAddressInt {
    InitData::from_key(public_key)
        .with_wallet_id(WALLET_ID)
        .compute_addr(workchain_id)
        .trust_me()
}

pub static DETAILS: TonWalletDetails = TonWalletDetails {
    requires_separate_deploy: false,
    min_amount: 1, // 0.000000001 TON
    supports_payload: true,
    supports_multiple_owners: false,
    expiration_time: 0,
};

/// `HighloadWalletV2` init data
#[derive(Clone, Copy)]
pub struct InitData {
    pub wallet_id: u32,
    pub last_cleaned: u64,
    pub public_key: UInt256,
}

impl InitData {
    pub fn public_key(&self) -> &[u8; 32] {
        self.public_key.as_slice()
    }

    pub fn from_key(key: &PublicKey) -> Self {
        Self {
            wallet_id: 0,
            last_cleaned: 0,
            public_key: key.as_bytes().into(),
        }
    }

    pub fn with_wallet_id(mut self, id: u32) -> Self {
        self.wallet_id = id;
        self
    }

    pub fn compute_addr(&self, workchain_id: i8) -> Result<MsgAddressInt> {
        let init_state = self.make_state_init()?.serialize()?;
        let hash = init_state.repr_hash();
        Ok(MsgAddressInt::AddrStd(MsgAddrStd {
            anycast: None,
            workchain_id,
            address: hash.into(),
        }))
    }

    pub fn make_state_init(&self) -> Result<ton_block::StateInit> {
        Ok(ton_block::StateInit {
            code: Some(nekoton_contracts::code::highload_wallet_v2()),
            data: Some(self.serialize()?),
            ..Default::default()
        })
    }

    pub fn serialize(&self) -> Result<Cell> {
        let mut data = BuilderData::new();
        data.append_u32(self.wallet_id)?
            .append_u64(self.last_cleaned)?
            .append_raw(self.public_key.as_slice(), 256)?
            .append_bit_zero()?;
        data.into_cell()
    }

    pub fn make_deploy_payload(&self, expire_at: u32) -> Result<(UInt256, BuilderData)> {
        let mut payload = BuilderData::new();
        payload
            .append_u32(self.wallet_id)?
            .append_u32(expire_at)?
            .append_u32(u32::MAX)?
            .append_bit_zero()?;

        let hash = payload.clone().into_cell()?.repr_hash();

        Ok((hash, payload))
    }

    pub fn make_transfer_payload(
        &self,
        gifts: &[Gift],
        expire_at: u32,
    ) -> Result<(UInt256, BuilderData)> {
        // Prepare messages array
        let mut messages = ton_types::HashmapE::with_bit_len(16);
        for (i, gift) in gifts.iter().enumerate() {
            let mut internal_message =
                ton_block::Message::with_int_header(ton_block::InternalMessageHeader {
                    ihr_disabled: true,
                    bounce: gift.bounce,
                    dst: gift.destination.clone(),
                    value: gift.amount.into(),
                    ..Default::default()
                });

            if let Some(body) = &gift.body {
                internal_message.set_body(body.clone());
            }

            if let Some(state_init) = &gift.state_init {
                internal_message.set_state_init(state_init.clone());
            }

            let mut item = BuilderData::new();
            item.append_u8(gift.flags)?
                .append_reference_cell(internal_message.serialize()?);

            let key = (i as u16).write_to_new_cell().unwrap().into();

            messages.set(key, &item.into())?;
        }

        let messages = messages.serialize()?;
        let messages_hash = messages.repr_hash();

        // Build payload
        let mut payload = BuilderData::new();
        payload
            .append_u32(self.wallet_id)?
            .append_u32(expire_at)?
            .append_raw(&messages_hash.as_slice()[28..32], 32)?
            .append_builder(&messages.into())?;

        let hash = payload.clone().into_cell()?.repr_hash();

        Ok((hash, payload))
    }
}

impl TryFrom<&Cell> for InitData {
    type Error = anyhow::Error;

    fn try_from(data: &Cell) -> Result<Self, Self::Error> {
        let mut cs = SliceData::from(data);
        Ok(Self {
            wallet_id: cs.get_next_u32()?,
            last_cleaned: cs.get_next_u64()?,
            public_key: UInt256::from_be_bytes(&cs.get_next_bytes(32)?),
        })
    }
}

/// `HighloadWalletV2` transfer info
#[derive(Clone)]
pub struct Gift {
    pub flags: u8,
    pub bounce: bool,
    pub destination: MsgAddressInt,
    pub amount: u64,
    pub body: Option<SliceData>,
    pub state_init: Option<ton_block::StateInit>,
}

const WALLET_ID: u32 = 0x00000000;

#[derive(thiserror::Error, Debug)]
enum HighloadWalletV2Error {
    #[error("Invalid init data")]
    InvalidInitData,
    #[error("Account is frozen")]
    AccountIsFrozen,
}
