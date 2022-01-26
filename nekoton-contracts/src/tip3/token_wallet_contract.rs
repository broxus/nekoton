use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

pub const TIP3_TOKEN_WALLET_CONTRACT_INTERFACE_ID: u32 = 0x4F479FA3;

/// Returns the token root address.
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `root: address`
///
pub fn root() -> &'static ton_abi::Function {
    declare_function! {
        name: "root",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("root", ParamType::Address)],
    }
}

/// Returns the token wallet balance.
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `balance: uint128`
///
pub fn balance() -> &'static ton_abi::Function {
    declare_function! {
        name: "balance",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("balance", ParamType::Uint(128))],
    }
}

/// Returns the token wallet code.
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `walletCode: cell`
///
pub fn wallet_code() -> &'static ton_abi::Function {
    declare_function! {
        name: "walletCode",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("walletCode", ParamType::Cell)],
    }
}

/// Called by another token wallet on transfer
///
/// # Type
/// Internal method (PARTIAL)
///
/// # Inputs
/// * `value: uint128` - amount of tokens
///
pub fn accept_transfer() -> &'static ton_abi::Function {
    declare_function! {
        function_id: 0x67A0B95F,
        name: "acceptTransfer",
        inputs: vec![Param::new("value", ParamType::Uint(128))],
        outputs: Vec::new(),
    }
}

/// Called by root token contract on mint
///
/// # Type
/// Internal method (PARTIAL)
///
/// # Inputs
/// * `value: uint128` - amount of tokens
///
pub fn accept_mint() -> &'static ton_abi::Function {
    declare_function! {
        function_id: 0x4384F298,
        name: "acceptMint",
        inputs: vec![Param::new("value", ParamType::Uint(128))],
        outputs: Vec::new(),
    }
}
