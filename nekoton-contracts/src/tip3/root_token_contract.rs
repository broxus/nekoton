use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

pub const INTERFACE_ID: u32 = 0x4371D8ED;

/// Returns the name of the token - e.g. `MyToken`.
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `name: string`
///
pub fn name() -> &'static ton_abi::Function {
    declare_function! {
        name: "name",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("name", ParamType::String)],
    }
}

/// Returns the symbol of the token. E.g. "HIX".
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `symbol: string`
///
pub fn symbol() -> &'static ton_abi::Function {
    declare_function! {
        name: "symbol",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("symbol", ParamType::String)],
    }
}

/// Returns the number of decimals the token uses - e.g. 8,
/// means to divide the token amount by 100000000 to get its user representation.
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `decimals: uint8`
///
pub fn decimals() -> &'static ton_abi::Function {
    declare_function! {
        name: "decimals",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("decimals", ParamType::Uint(8))],
    }
}

/// Returns the total token supply.
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `totalSupply: string`
///
pub fn total_supply() -> &'static ton_abi::Function {
    declare_function! {
        name: "totalSupply",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("totalSupply", ParamType::Uint(128))],
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

/// Called by token wallet on burn
///
/// # Type
/// Internal method (PARTIAL)
///
/// # Inputs
/// * `amount: uint128` - amount of tokens
///
pub fn accept_burn() -> &'static ton_abi::Function {
    declare_function! {
        function_id: 0x192B51B1,
        name: "acceptBurn",
        inputs: vec![
            Param::new("amount", ParamType::Uint(128)),
        ],
        outputs: Vec::new(),
    }
}
