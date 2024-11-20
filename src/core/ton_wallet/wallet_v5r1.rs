use std::convert::TryFrom;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use ton_block::{MsgAddrStd, MsgAddressInt, Serializable};
use ton_types::{BuilderData, Cell, IBitstring, SliceData, UInt256};

use nekoton_utils::*;

use super::{Gift, TonWalletDetails, TransferAction};
use crate::core::models::{Expiration, ExpireAt};
use crate::crypto::{SignedMessage, UnsignedMessage};

const SIGNED_EXTERNAL_PREFIX: u32 = 0x7369676E;
const ACTION_SEND_MSG_PREFIX: u32 = 0x0ec3c86d;

pub fn prepare_deploy(
    clock: &dyn Clock,
    public_key: &PublicKey,
    workchain: i8,
    expiration: Expiration,
) -> Result<Box<dyn UnsignedMessage>> {
    let init_data = InitData::from_key(public_key);
    let dst = compute_contract_address(public_key, workchain);
    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst,
            ..Default::default()
        });

    message.set_state_init(init_data.make_state_init()?);

    let expire_at = ExpireAt::new(clock, expiration);
    let (hash, payload) = init_data.make_transfer_payload(None, expire_at.timestamp)?;

    Ok(Box::new(UnsignedWalletV5 {
        init_data,
        gifts: Vec::new(),
        payload,
        message,
        expire_at,
        hash,
    }))
}

pub fn prepare_transfer(
    clock: &dyn Clock,
    public_key: &PublicKey,
    current_state: &ton_block::AccountStuff,
    seqno_offset: u32,
    gifts: Vec<Gift>,
    expiration: Expiration,
) -> Result<TransferAction> {
    if gifts.len() > MAX_MESSAGES {
        return Err(WalletV5Error::TooManyGifts.into());
    }

    let (mut init_data, with_state_init) = match &current_state.storage.state {
        ton_block::AccountState::AccountActive { state_init, .. } => match &state_init.data {
            Some(data) => (InitData::try_from(data)?, false),
            None => return Err(WalletV5Error::InvalidInitData.into()),
        },
        ton_block::AccountState::AccountFrozen { .. } => {
            return Err(WalletV5Error::AccountIsFrozen.into())
        }
        ton_block::AccountState::AccountUninit => (InitData::from_key(public_key), true),
    };

    init_data.seqno += seqno_offset;

    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst: current_state.addr.clone(),
            ..Default::default()
        });

    if with_state_init {
        message.set_state_init(init_data.make_state_init()?);
    }

    let expire_at = ExpireAt::new(clock, expiration);
    let (hash, payload) = init_data.make_transfer_payload(gifts.clone(), expire_at.timestamp)?;

    Ok(TransferAction::Sign(Box::new(UnsignedWalletV5 {
        init_data,
        gifts,
        payload,
        hash,
        expire_at,
        message,
    })))
}

#[derive(Clone)]
struct UnsignedWalletV5 {
    init_data: InitData,
    gifts: Vec<Gift>,
    payload: BuilderData,
    hash: UInt256,
    expire_at: ExpireAt,
    message: ton_block::Message,
}

impl UnsignedMessage for UnsignedWalletV5 {
    fn refresh_timeout(&mut self, clock: &dyn Clock) {
        if !self.expire_at.refresh(clock) {
            return;
        }

        let (hash, payload) = self
            .init_data
            .make_transfer_payload(self.gifts.clone(), self.expire_at())
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
        payload.append_raw(signature, signature.len() * 8)?;

        let mut message = self.message.clone();
        message.set_body(SliceData::load_builder(payload)?);

        Ok(SignedMessage {
            message,
            expire_at: self.expire_at(),
        })
    }

    fn sign_with_pruned_payload(
        &self,
        signature: &[u8; ed25519_dalek::SIGNATURE_LENGTH],
        prune_after_depth: u16,
    ) -> Result<SignedMessage> {
        let mut payload = self.payload.clone();
        payload.append_raw(signature, signature.len() * 8)?;
        let body = payload.into_cell()?;

        let mut message = self.message.clone();
        message.set_body(prune_deep_cells(&body, prune_after_depth)?);

        Ok(SignedMessage {
            message,
            expire_at: self.expire_at(),
        })
    }
}

pub static CODE_HASH: &[u8; 32] = &[
    0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
    0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
];

pub fn is_wallet_v5r1(code_hash: &UInt256) -> bool {
    code_hash.as_slice() == CODE_HASH
}

pub fn compute_contract_address(public_key: &PublicKey, workchain_id: i8) -> MsgAddressInt {
    InitData::from_key(public_key)
        .with_is_signature_allowed(true)
        .with_wallet_id(WALLET_ID)
        .compute_addr(workchain_id)
        .trust_me()
}

pub static DETAILS: TonWalletDetails = TonWalletDetails {
    requires_separate_deploy: false,
    min_amount: 1, // 0.000000001 TON
    max_messages: MAX_MESSAGES,
    supports_payload: true,
    supports_state_init: true,
    supports_multiple_owners: false,
    supports_code_update: false,
    expiration_time: 0,
    required_confirmations: None,
};

const MAX_MESSAGES: usize = 250;

/// `WalletV5` init data
#[derive(Clone)]
pub struct InitData {
    pub is_signature_allowed: bool,
    pub seqno: u32,
    pub wallet_id: u32,
    pub public_key: UInt256,
    pub extensions: Option<Cell>,
}

impl InitData {
    pub fn public_key(&self) -> &[u8; 32] {
        self.public_key.as_slice()
    }

    pub fn from_key(key: &PublicKey) -> Self {
        Self {
            is_signature_allowed: false,
            seqno: 0,
            wallet_id: 0,
            public_key: key.as_bytes().into(),
            extensions: Default::default(),
        }
    }

    pub fn with_is_signature_allowed(mut self, is_allowed: bool) -> Self {
        self.is_signature_allowed = is_allowed;
        self
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
            code: Some(nekoton_contracts::wallets::code::wallet_v5r1()),
            data: Some(self.serialize()?),
            ..Default::default()
        })
    }

    pub fn serialize(&self) -> Result<Cell> {
        let mut data = BuilderData::new();
        data.append_bit_bool(self.is_signature_allowed)?
            .append_u32(self.seqno)?
            .append_u32(self.wallet_id)?
            .append_raw(self.public_key.as_slice(), 256)?;

        if let Some(extensions) = &self.extensions {
            data.append_bit_one()?
                .checked_append_reference(extensions.clone())?;
        } else {
            data.append_bit_zero()?;
        }

        data.into_cell()
    }

    pub fn make_transfer_payload(
        &self,
        gifts: impl IntoIterator<Item = Gift>,
        expire_at: u32,
    ) -> Result<(UInt256, BuilderData)> {
        // Check if signatures are allowed
        if !self.is_signature_allowed {
            return if self.extensions.is_none() {
                Err(WalletV5Error::WalletLocked.into())
            } else {
                Err(WalletV5Error::SignaturesDisabled.into())
            };
        }

        let mut payload = BuilderData::new();

        // insert prefix
        payload
            .append_u32(SIGNED_EXTERNAL_PREFIX)?
            .append_u32(self.wallet_id)?
            .append_u32(expire_at)?
            .append_u32(self.seqno)?;

        // create internal message
        for gift in gifts {
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

            let action = ton_block::OutAction::SendMsg {
                mode: gift.flags,
                out_msg: internal_message,
            };

            payload
                .append_u32(ACTION_SEND_MSG_PREFIX)?
                .checked_append_reference(action.serialize()?)?;
        }

        let hash = payload.clone().into_cell()?.repr_hash();

        Ok((hash, payload))
    }
}

impl TryFrom<&Cell> for InitData {
    type Error = anyhow::Error;

    fn try_from(data: &Cell) -> Result<Self, Self::Error> {
        let mut cs = SliceData::load_cell_ref(data)?;
        Ok(Self {
            is_signature_allowed: cs.get_next_bit()?,
            seqno: cs.get_next_u32()?,
            wallet_id: cs.get_next_u32()?,
            public_key: UInt256::from_be_bytes(&cs.get_next_bytes(32)?),
            extensions: cs.get_next_dictionary()?,
        })
    }
}

const WALLET_ID: u32 = 0x7FFFFF11;

#[derive(thiserror::Error, Debug)]
enum WalletV5Error {
    #[error("Invalid init data")]
    InvalidInitData,
    #[error("Account is frozen")]
    AccountIsFrozen,
    #[error("Too many outgoing messages")]
    TooManyGifts,
    #[error("Signatures are disabled")]
    SignaturesDisabled,
    #[error("Wallet locked")]
    WalletLocked,
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::PublicKey;
    use ton_block::AccountState;

    use crate::core::ton_wallet::wallet_v5r1::{compute_contract_address, InitData, WALLET_ID};

    #[test]
    fn state_init() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgECFgEAAucAAm6ADZRqTnEksRaYvpXRMbgzB92SzFv/19WbfQQgdDo7lYwEWQnKBnPzD1AAAXPmjwdAEj9i9OgmAgEAUYAAAAG///+IyIPTKTihvw1MFdzCAl7NQWIaeY9xhjENsss4FdrN+FAgART/APSkE/S88sgLAwIBIAYEAQLyBQEeINcLH4IQc2lnbrry4Ip/EQIBSBAHAgEgCQgAGb5fD2omhAgKDrkPoCwCASANCgIBSAwLABGyYvtRNDXCgCAAF7Ml+1E0HHXIdcLH4AIBbg8OABmvHfaiaEAQ65DrhY/AABmtznaiaEAg65Drhf/AAtzQINdJwSCRW49jINcLHyCCEGV4dG69IYIQc2ludL2wkl8D4IIQZXh0brqOtIAg1yEB0HTXIfpAMPpE+Cj6RDBYvZFb4O1E0IEBQdch9AWDB/QOb6ExkTDhgEDXIXB/2zzgMSDXSYECgLmRMOBw4hIRAeaO8O2i7fshgwjXIgKDCNcjIIAg1yHTH9Mf0x/tRNDSANMfINMf0//XCgAK+QFAzPkQmiiUXwrbMeHywIffArNQB7Dy0IRRJbry4IVQNrry4Ib4I7vy0IgikvgA3gGkf8jKAMsfAc8Wye1UIJL4D95w2zzYEgP27aLt+wL0BCFukmwhjkwCIdc5MHCUIccAs44tAdcoIHYeQ2wg10nACPLgkyDXSsAC8uCTINcdBscSwgBSMLDy0InXTNc5MAGk6GwShAe78uCT10rAAPLgk+1V4tIAAcAAkVvg69csCBQgkXCWAdcsCBwS4lIQseMPINdKFRQTABCTW9sx4ddM0AByMNcsCCSOLSHy4JLSAO1E0NIAURO68tCPVFAwkTGcAYEBQNch1woA8uCO4sjKAFjPFsntVJPywI3iAJYB+kAB+kT4KPpEMFi68uCR7UTQgQFB1xj0BQSdf8jKAEAEgwf0U/Lgi44UA4MH9Fvy4Iwi1woAIW4Bs7Dy0JDiyFADzxYS9ADJ7VQ=").unwrap().as_slice()).unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        if let AccountState::AccountActive { state_init } = state.storage.state() {
            let init_data = InitData::try_from(state_init.data().unwrap())?;
            assert_eq!(init_data.is_signature_allowed, true);
            assert_eq!(
                init_data.public_key.to_hex_string(),
                "9107a65271437e1a982bb98404bd9a82c434f31ee30c621b6596702bb59bf0a0"
            );
            assert_eq!(init_data.wallet_id, WALLET_ID);
            assert_eq!(init_data.extensions, None);

            let public_key = PublicKey::from_bytes(init_data.public_key.as_slice())?;
            let address = compute_contract_address(&public_key, 0);
            assert_eq!(
                address.to_string(),
                "0:6ca35273892588b4c5f4ae898dc1983eec9662dffebeacdbe82103a1d1dcac60"
            );
        }

        Ok(())
    }
}
