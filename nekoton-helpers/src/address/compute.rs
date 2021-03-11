use anyhow::Error;
use ed25519_dalek::{Keypair, PublicKey};
use ton_block::{MsgAddrStd, MsgAddressInt, Serializable, StateInit};
use ton_sdk::ContractImage;
use ton_types::{BuilderData, Cell, IBitstring, Result, SliceData, UInt256};

const SAFE_MULTISIG_WALLET_CODE: &[u8] = include_bytes!("../contracts/SafeMultisigWallet.tvc");
const SAFE_MULTISIG_WALLET24H_CODE: &[u8] =
    include_bytes!("../contracts/SafeMultisigWallet24h.tvc");
const SETCODE_MULTISIG_WALLET_CODE: &[u8] =
    include_bytes!("../contracts/SetcodeMultisigWallet.tvc");
const SURF_WALLET_CODE: &[u8] = include_bytes!("../contracts/Surf.tvc");
const WALLET_V3_CODE: &[u8] = include_bytes!("../contracts/wallet_code.boc");

pub const SAFE_MULTISIG_WALLET: u8 = 0;
pub const SAFE_MULTISIG_WALLET24H: u8 = 1;
pub const SETCODE_MULTISIG_WALLET: u8 = 2;
pub const SURF_WALLET: u8 = 3;
pub const WALLET_V3: u8 = 4;

fn msg_addr_int_to_std(addr: &MsgAddressInt) -> anyhow::Result<MsgAddrStd, Error> {
    match addr {
        MsgAddressInt::AddrStd(a) => Ok(a.clone()),
        MsgAddressInt::AddrVar(_) => {
            anyhow::bail!("AddrVar is not supported")
        }
    }
}

pub fn compute(
    pk: &ed25519_dalek::PublicKey,
    contract_type: u8,
    workchain: i32,
) -> anyhow::Result<MsgAddrStd, Error> {
    use std::io::Cursor;
    let contract = match contract_type {
        SAFE_MULTISIG_WALLET => {
            ContractImage::from_state_init_and_key(&mut Cursor::new(SAFE_MULTISIG_WALLET_CODE), pk)
        }
        SAFE_MULTISIG_WALLET24H => ContractImage::from_state_init_and_key(
            &mut Cursor::new(SAFE_MULTISIG_WALLET24H_CODE),
            pk,
        ),
        SETCODE_MULTISIG_WALLET => ContractImage::from_state_init_and_key(
            &mut Cursor::new(SETCODE_MULTISIG_WALLET_CODE),
            pk,
        ),
        SURF_WALLET => {
            ContractImage::from_state_init_and_key(&mut Cursor::new(SURF_WALLET_CODE), pk)
        }

        WALLET_V3 => {
            return compute_deposit_address(pk, 0x4BA92D8A).map_err(|e| Error::msg(e.to_string()))
        }
        n => anyhow::bail!("Compute not implemented for {}", n),
    }
    .map_err(|e| Error::msg(e.to_string()).context("Failed constructing contract"))?;
    msg_addr_int_to_std(&contract.msg_address(workchain))
}

/// Compute deposit address from key and wallet id
pub fn compute_deposit_address(key: &PublicKey, id: u32) -> anyhow::Result<MsgAddrStd> {
    msg_addr_int_to_std(
        &InitData::from_key(&key)
            .with_wallet_id(id)
            .compute_addr()
            .map_err(|e| Error::msg(e.to_string()))?,
    )
}

/// WalletV3 init data
struct InitData {
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

    pub fn compute_addr(&self) -> Result<MsgAddressInt> {
        let init_state = self.make_state_init()?.serialize()?;
        let hash = init_state.repr_hash();
        MsgAddressInt::with_standart(None, 0, hash.into())
    }

    pub fn make_state_init(&self) -> Result<StateInit> {
        Ok(StateInit {
            code: Some(load_code()),
            data: Some(self.serialize()?),
            ..Default::default()
        })
    }

    pub fn deserialize(data: Cell) -> Result<Self> {
        let mut slice: SliceData = data.into();
        let seqno = slice.get_next_u32()?;
        let wallet_id = slice.get_next_u32()?;
        let public_key = slice.get_next_bytes(32)?.into();

        Ok(InitData {
            seqno,
            wallet_id,
            public_key,
        })
    }

    pub fn serialize(&self) -> Result<Cell> {
        let mut data = BuilderData::new();
        data.append_u32(self.seqno)?
            .append_u32(self.wallet_id)?
            .append_raw(self.public_key.as_slice(), 256)?;
        data.into_cell()
    }
}

fn load_code() -> Cell {
    ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(WALLET_V3_CODE)).unwrap()
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;

    use crate::address::compute::{compute, SAFE_MULTISIG_WALLET, SURF_WALLET, WALLET_V3};
    use crate::address::pack_std_smc_addr;

    fn default_pubkey() -> ed25519_dalek::PublicKey {
        ed25519_dalek::PublicKey::from_bytes(
            &*hex::decode("e5a4307499c781b50ce41ee1e1c656b6db62ea4806568378f11ddc2b08d40773")
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_v3() {
        let pk = default_pubkey();
        let addr = compute(&pk, WALLET_V3, 0).unwrap();
        assert_eq!(
            pack_std_smc_addr(true, &addr, false),
            "UQDIsJmoySkJdZEX5NNj02aix0BXE4-Ym4zcGFCfmo0xaeFc"
        );
    }

    #[test]
    fn test_surf() {
        let pk = default_pubkey();
        let addr = compute(&pk, SURF_WALLET, 0).unwrap();
        assert_eq!(
            pack_std_smc_addr(true, &addr, true),
            "EQC5aPHGTz9B4EaZpq7wYq-eoKWiOFXwUx05vURmxwl4W4Jn"
        );
    }
}
