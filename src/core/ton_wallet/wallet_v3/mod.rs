use std::convert::TryFrom;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use ton_block::{MsgAddrStd, MsgAddressInt, Serializable};
use ton_types::{BuilderData, Cell, IBitstring, SliceData, UInt256};

use super::TonWalletDetails;
use crate::contracts;
use crate::utils::*;

#[cfg(feature = "wallet")]
mod wallet_integration;
#[cfg(feature = "wallet")]
pub use wallet_integration::*;

const WALLET_V3_HASH: [u8; 32] = [
    0x84, 0xda, 0xfa, 0x44, 0x9f, 0x98, 0xa6, 0x98, 0x77, 0x89, 0xba, 0x23, 0x23, 0x58, 0x07, 0x2b,
    0xc0, 0xf7, 0x6d, 0xc4, 0x52, 0x40, 0x02, 0xa5, 0xd0, 0x91, 0x8b, 0x9a, 0x75, 0xd2, 0xd5, 0x99,
];

pub fn is_wallet_v3(code_hash: &UInt256) -> bool {
    code_hash.as_slice() == &WALLET_V3_HASH
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

/// `WalletV3` init data
#[derive(Clone)]
pub struct InitData {
    pub seqno: u32,
    pub wallet_id: u32,
    pub public_key: UInt256,
}

impl InitData {
    pub fn public_key(&self) -> &[u8; 32] {
        self.public_key.as_slice()
    }

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
        gift: Option<Gift>,
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
        if let Some(gift) = gift {
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

            // append it to the body
            payload
                .append_u8(gift.flags)
                .convert()?
                .append_reference_cell(internal_message.serialize().convert()?);
        }

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

/// `WalletV3` transfer info
#[derive(Clone)]
pub struct Gift {
    pub flags: u8,
    pub bounce: bool,
    pub destination: MsgAddressInt,
    pub amount: u64,
    pub body: Option<SliceData>,
    pub state_init: Option<ton_block::StateInit>,
}

const WALLET_ID: u32 = 0x4BA92D8A;
