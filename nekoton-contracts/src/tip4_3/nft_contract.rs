use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

pub const INTERFACE_ID: u32 = 0x4DF6250B;

///Get contract index code
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `code: cell` - Index code of the contract
///
pub fn index_code() -> &'static ton_abi::Function {
    declare_function! {
        name: "indexBCode",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("code", ParamType::Cell)],
    }
}

///Get contract index code hash
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `hash: uint256` - Index code hash of the contract
///
pub fn index_code_hash() -> &'static ton_abi::Function {
    declare_function! {
        name: "indexBCode",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("hash", ParamType::Uint(256))],
    }
}

///Resolve contract index
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
/// * `collection: address` - collection token contract address
/// * `owner: address` - token owner contract address
///
/// # Outputs
/// * `index: address` - index contract address
///
pub fn resolve_index() -> &'static ton_abi::Function {
    declare_function! {
        name: "resolveIndex",
        inputs: vec![
            Param::new("answerId", ParamType::Uint(32)),
            Param::new("collection", ParamType::Address),
            Param::new("owner", ParamType::Address),
        ],
        outputs: vec![Param::new("indexBasis", ParamType::Address)],
    }
}
