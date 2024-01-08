use nekoton_abi::num_bigint::BigUint;
use nekoton_utils::*;
use serde::{Deserialize, Serialize};
use ton_block::MsgAddressInt;

pub use self::root_token_contract::RootTokenContractState;
pub use self::token_wallet_contract::TokenWalletContractState;

mod root_token_contract;
mod token_wallet_contract;

define_string_enum!(
    #[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub enum TokenWalletVersion {
        /// Third iteration of token wallets, but with fixed bugs
        /// [implementation](https://github.com/broxus/ton-eth-bridge-token-contracts/tree/74905260499d79cf7cb0d89a6eb572176fc1fcd5)
        OldTip3v4,
        /// Latest iteration with completely new standard
        /// [implementation](https://github.com/broxus/ton-eth-bridge-token-contracts/tree/9168190f218fd05a64269f5f24295c69c4840d94)
        Tip3,
    }
);

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RootTokenContractDetails {
    /// Token ecosystem version
    pub version: TokenWalletVersion,
    /// Full currency name
    pub name: String,
    /// Short currency name
    pub symbol: String,
    /// Decimals
    pub decimals: u8,
    /// Root owner contract address. Used as proxy address in Tip3v1
    #[serde(with = "serde_address")]
    pub owner_address: MsgAddressInt,
    #[serde(with = "serde_string")]
    pub total_supply: BigUint,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenWalletDetails {
    /// Linked root token contract address
    #[serde(with = "serde_address")]
    pub root_address: MsgAddressInt,

    /// Owner wallet address
    #[serde(with = "serde_address")]
    pub owner_address: MsgAddressInt,

    #[serde(with = "serde_string")]
    pub balance: BigUint,
}

#[derive(thiserror::Error, Debug)]
pub enum Tip3Error {
    #[error("Unknown version")]
    UnknownVersion,
    #[error("Wallet not deployed")]
    WalletNotDeployed,
}
