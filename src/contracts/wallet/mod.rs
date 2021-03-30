mod multisig;
mod wallet_v3;

use anyhow::Result;
use dyn_clone::DynClone;
use ed25519_dalek::PublicKey;
use serde::{Deserialize, Serialize};
use ton_block::MsgAddressInt;
use ton_types::SliceData;

pub use multisig::MultisigType;

pub const DEFAULT_WORKCHAIN: i8 = 0;

pub struct Wallet {
    public_key: PublicKey,
    contract_type: ContractType,
}

impl Wallet {
    pub fn new(public_key: PublicKey, contract_type: ContractType) -> Self {
        Self {
            public_key,
            contract_type,
        }
    }

    pub fn compute_address(&self) -> MsgAddressInt {
        compute_address(&self.public_key, self.contract_type, DEFAULT_WORKCHAIN)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn contract_type(&self) -> ContractType {
        self.contract_type
    }

    pub fn prepare_deploy(&self, expire_at: u32) -> Result<Box<dyn UnsignedMessage>> {
        match self.contract_type {
            ContractType::Multisig(multisig_type) => {
                multisig::prepare_deploy(&self.public_key, multisig_type, expire_at)
            }
            ContractType::WalletV3 => wallet_v3::prepare_deploy(&self.public_key, expire_at),
        }
    }

    pub fn prepare_transfer(
        &self,
        current_state: &ton_block::AccountStuff,
        destination: MsgAddressInt,
        amount: u64,
        bounce: bool,
        body: Option<SliceData>,
        expire_at: u32,
    ) -> Result<TransferAction> {
        match self.contract_type {
            ContractType::Multisig(_) => multisig::prepare_transfer(
                &self.public_key,
                current_state,
                destination,
                amount,
                bounce,
                body,
                expire_at,
            ),
            ContractType::WalletV3 => wallet_v3::prepare_transfer(
                &self.public_key,
                current_state,
                destination,
                amount,
                bounce,
                body,
                expire_at,
            ),
        }
    }
}

pub enum TransferAction {
    DeployFirst,
    Sign(Box<dyn UnsignedMessage>),
}

pub trait UnsignedMessage: DynClone {
    fn hash(&self) -> &[u8];
    fn sign(self, signature: &[u8; ed25519_dalek::SIGNATURE_LENGTH]) -> Result<SignedMessage>;
}

dyn_clone::clone_trait_object!(UnsignedMessage);

pub struct SignedMessage {
    message: ton_block::Message,
    expire_at: u32,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContractType {
    Multisig(MultisigType),
    WalletV3,
}

pub fn compute_address(
    public_key: &PublicKey,
    contract_type: ContractType,
    workchain_id: i8,
) -> MsgAddressInt {
    match contract_type {
        ContractType::Multisig(multisig_type) => {
            multisig::compute_contract_address(public_key, multisig_type, workchain_id)
        }
        ContractType::WalletV3 => wallet_v3::compute_contract_address(public_key, workchain_id),
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use pretty_assertions::assert_eq;
    use ton_block::MsgAddressInt;

    use crate::helpers::address::compute::msg_addr_int_to_std;
    use crate::helpers::address::{
        compute_address, msg_addr_from_str, pack_std_smc_addr, ContractType,
    };

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
        let addr = compute_address(&pk, ContractType::WalletV3, 0);
        assert_eq!(
            pack_std_smc_addr(true, &addr, false),
            "UQDIsJmoySkJdZEX5NNj02aix0BXE4-Ym4zcGFCfmo0xaeFc"
        );
    }

    #[test]
    fn test_surf() {
        let pk = default_pubkey();
        let addr = compute_address(&pk, ContractType::SurfWallet, 0);
        assert_eq!(
            pack_std_smc_addr(true, &addr, true),
            "EQC5aPHGTz9B4EaZpq7wYq-eoKWiOFXwUx05vURmxwl4W4Jn"
        );
    }
    #[test]
    fn test_multisig() {
        let pk = ed25519_dalek::PublicKey::from_bytes(
            &*hex::decode("1e6e5912e156d02dd4769caae5c5d8ee9058726c75d263bafc642d64669cc46d")
                .unwrap(),
        )
        .unwrap();
        let addr = compute_address(&pk, ContractType::SafeMultisigWallet, 0);

        let expected_address = msg_addr_int_to_std(
            &MsgAddressInt::from_str(
                "0:5C3BCF647CDFD678FBEC95754ACCB2668F7CD651F60FCDD9689C1829A94CFEE6",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(addr, expected_address);
    }

    #[test]
    fn test_multisig24() {
        let pk = ed25519_dalek::PublicKey::from_bytes(
            &*hex::decode("32e6c4634145353e8ee270adf837beb519e02a59c503d206e85c5e25c2be535b")
                .unwrap(),
        )
        .unwrap();
        let addr = compute_address(&pk, ContractType::SafeMultisigWallet24h, 0);
        let expected_address =
            msg_addr_from_str("0:2d0f4b099b346f51cb1b736188b1ee19d71c2ac4688da3fa126020ac2b5a2b5c")
                .unwrap();
        assert_eq!(addr, expected_address);
    }

    #[test]
    fn test_setcode() {
        let pk = ed25519_dalek::PublicKey::from_bytes(
            &*hex::decode("32e6c4634145353e8ee270adf837beb519e02a59c503d206e85c5e25c2be535b")
                .unwrap(),
        )
        .unwrap();
        let addr = compute_address(&pk, ContractType::SetcodeMultisigWallet, 0);
        let expected_address =
            msg_addr_from_str("0:9d368d911c9444e7805d7ea0fd8d05005f3e8a739d053ed1622c2313cd99a15d")
                .unwrap();
        assert_eq!(addr, expected_address);
    }
}
