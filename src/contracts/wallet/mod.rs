use std::alloc::Global;
use std::convert::TryFrom;
use std::str::FromStr;

use anyhow::Result;
use dyn_clone::DynClone;
use ed25519_dalek::PublicKey;
use serde::{Deserialize, Serialize};
use ton_abi::{Function, ParamType, Token, TokenValue, Uint};
use ton_block::{Message, MsgAddress, MsgAddressInt, Transaction};
use ton_executor::BlockchainConfig;
use ton_types::SliceData;

pub use multisig::MultisigType;

use crate::contracts::abi::{eth_event, ton_token_wallet};
use crate::contracts::utils::functions::FunctionBuilder;
use crate::helpers::abi::FunctionAbi;
use crate::utils::{TrustMe, UInt128};

mod multisig;
mod wallet_v3;

pub const DEFAULT_WORKCHAIN: i8 = 0;

pub struct Wallet {
    public_key: PublicKey,
    contract_type: ContractType,
}

#[derive(Copy, Clone)]
pub enum ParsingContext {
    MainWallet,
    TokenWallet,
}

///Transactions from bridge
#[derive(Copy, Clone)]
pub enum TransactionAdditionalInfo {
    RegularTransaction,
    //None
    //From internal input message
    // Events
    TokenWalletDeployed(MsgAddress),
    //
    EthEventStatusChanged,
    //
    TonEventStatusChanged, //

    // Token transaction
    TokenTransfer,
    ///Incoming
    TokenSwapBack,
    //
    TokenMint,
    //
    TokensBounced(BounceCallback), //

    // DePool transaction
    DePoolOrdinaryStakeTransaction,
    //
    DePoolOnRoundCompleteTransaction, //

    // Multisig transaction
    MultisigDeploymentTransaction,
    //
    MultisigSubmitTransaction,
    //
    MultisigConfirmTransaction,
}

struct BounceCallback {
    token_wallet: MsgAddress,
    token_root: MsgAddress,
    ammount: Uint,
    bounced_from: MsgAddress,
    updated_balance: Uint,
}

struct Mint{

}

impl TryFrom<Vec<Token>> for BounceCallback {
    type Error = ();

    fn try_from(value: Vec<Token>) -> Result<Self, Self::Error> {
        if value.len() != 5 {
            return Err(Self::Error);
        }
        let token_wallet = &value[0];
        let token_root = &value[1];
        let ammount = &value[2];
        let bounced_from = &value[3];
        let updated_balance = &value[4];

        let token_wallet = match token_wallet {
            TokenValue::Address(a) => a.clone(),
            _ => return Err(Self::Error)
        };
        let token_root = match token_root {
            TokenValue::Address(a) => a.clone(),
            _ => return Err(Self::Error)
        };
        let ammount = match ammount {
            TokenValue::Uint(a) => a.clone(),
            _ => return Err(Self::Error)
        };
        let bounced_from = match bounced_from {
            TokenValue::Address(a) => a.clone(),
            _ => return Err(Self::Error)
        };
        let updated_balance = match updated_balance {
            TokenValue::Uint(a) => a.clone(),
            _ => return Err(Self::Error)
        };
        Ok(BounceCallback {
            token_wallet,
            token_root,
            ammount,
            bounced_from,
            updated_balance,
        })
    }
}

//todo normal name
fn main_wallet_parse(tx: &Transaction) -> Option<TransactionAdditionalInfo> {
    use super::utils::functions::FunctionBuilder;
    use ton_abi::{Param, ParamType};
    let wallet_deploy = FunctionBuilder::new("notifyWalletDeployed")
        .in_arg("root", ParamType::Address)
        .build();
    let abi_parser = FunctionAbi::new(&wallet_deploy).trust_me();
    if let Ok(a) = abi_parser.parse(tx) {
        let address = match &a.get(0)?.value {
            TokenValue::Address(ad) => { TransactionAdditionalInfo::TokenWalletDeployed(ad.clone()) }
            _ => TransactionAdditionalInfo::RegularTransaction
        };
        return Some(address);
    };

    l
    todo!()
    // Ok(())
}

fn token_wallet_parse(tx: &Transaction) -> Option<TransactionAdditionalInfo> {
    let transfer_family = ["transferToRecipient", "transfer", "transferFrom", "internalTransfer", "internalTransferFrom"]
        .iter()
        .map(|x| FunctionAbi::new(ton_token_wallet().function(x).trust_me()).trust_me().parse(tx))
        .collect::<Result<Vec<_>>>().is_ok();
    if transfer_family {
        Ok(TransactionAdditionalInfo::TokenTransfer)
    }
    let tokens_bounced = FunctionBuilder::new("tokensBouncedCallback")
        .in_arg("token_wallet", ParamType::Address)
        .in_arg("token_root", ParamType::Address)
        .in_arg("amount", ParamType::Uint(128))
        .in_arg("bounced_from", ParamType::Address)
        .in_arg("updated_balance", ParamType::Uint(128))
        .build();

    let abi_parser = FunctionAbi::new(&eth_event_status_changed).trust_me();

    if let Ok(a) = abi_parser.parse(tx) {
        let info = BounceCallback::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokensBounced(info));
    };
    todo!()
    // let token_transfer = ton_token_wallet().function()
}


pub fn parse_event(
    tx: &Transaction,
    ctx: ParsingContext,
    config: BlockchainConfig,
) -> Option<TransactionAdditionalInfo> {
    use crate::helpers;
    todo!()
    // match ctx {
    //     ParsingContext::MainWallet => match () {},
    //     ParsingContext::TokenWallet => {}
    // }
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

#[derive(Clone)]
pub enum TransferAction {
    DeployFirst,
    Sign(Box<dyn UnsignedMessage>),
}

pub trait UnsignedMessage: DynClone {
    fn hash(&self) -> &[u8];
    fn sign(&self, signature: &[u8; ed25519_dalek::SIGNATURE_LENGTH]) -> Result<SignedMessage>;
}

dyn_clone::clone_trait_object!(UnsignedMessage);

#[derive(Clone)]
pub struct SignedMessage {
    pub message: ton_block::Message,
    pub expire_at: u32,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContractType {
    Multisig(MultisigType),
    WalletV3,
}

impl FromStr for ContractType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "WalletV3" => Self::WalletV3,
            s => Self::Multisig(MultisigType::from_str(s)?),
        })
    }
}

impl std::fmt::Display for ContractType {
    fn fmt(&self, f: &'_ mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::WalletV3 => f.write_str("WalletV3"),
            Self::Multisig(multisig_type) => multisig_type.fmt(f),
        }
    }
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

    use super::*;

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
            addr,
            MsgAddressInt::from_str(
                "0:c8b099a8c92909759117e4d363d366a2c74057138f989b8cdc18509f9a8d3169"
            )
                .unwrap()
        );
    }

    #[test]
    fn test_surf() {
        let pk = default_pubkey();
        let addr = compute_address(&pk, ContractType::Multisig(MultisigType::SurfWallet), 0);
        assert_eq!(
            addr,
            MsgAddressInt::from_str(
                "0:b968f1c64f3f41e04699a6aef062af9ea0a5a23855f0531d39bd4466c709785b"
            )
                .unwrap()
        );
    }

    #[test]
    fn test_multisig() {
        let pk = ed25519_dalek::PublicKey::from_bytes(
            &*hex::decode("1e6e5912e156d02dd4769caae5c5d8ee9058726c75d263bafc642d64669cc46d")
                .unwrap(),
        )
            .unwrap();
        let addr = compute_address(
            &pk,
            ContractType::Multisig(MultisigType::SafeMultisigWallet),
            0,
        );
        assert_eq!(
            addr,
            MsgAddressInt::from_str(
                "0:5C3BCF647CDFD678FBEC95754ACCB2668F7CD651F60FCDD9689C1829A94CFEE6",
            )
                .unwrap()
        );
    }

    #[test]
    fn test_multisig24() {
        let pk = ed25519_dalek::PublicKey::from_bytes(
            &*hex::decode("32e6c4634145353e8ee270adf837beb519e02a59c503d206e85c5e25c2be535b")
                .unwrap(),
        )
            .unwrap();
        let addr = compute_address(
            &pk,
            ContractType::Multisig(MultisigType::SafeMultisigWallet24h),
            0,
        );
        assert_eq!(
            addr,
            MsgAddressInt::from_str(
                "0:2d0f4b099b346f51cb1b736188b1ee19d71c2ac4688da3fa126020ac2b5a2b5c"
            )
                .unwrap()
        );
    }

    #[test]
    fn test_setcode() {
        let pk = ed25519_dalek::PublicKey::from_bytes(
            &*hex::decode("32e6c4634145353e8ee270adf837beb519e02a59c503d206e85c5e25c2be535b")
                .unwrap(),
        )
            .unwrap();
        let addr = compute_address(
            &pk,
            ContractType::Multisig(MultisigType::SetcodeMultisigWallet),
            0,
        );
        assert_eq!(
            addr,
            MsgAddressInt::from_str(
                "0:9d368d911c9444e7805d7ea0fd8d05005f3e8a739d053ed1622c2313cd99a15d"
            )
                .unwrap()
        );
    }

    #[test]
    fn test_val() {
        let eth_event_status_changed = eth_event().function("_status").trust_me();
    }
}
