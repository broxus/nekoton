use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

pub const INTERFACE_ID: u32 = 0x4387BBFB;

///Get contract index basis code
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `code: cell` - Index basic code of the contract
///
pub fn index_basis_code() -> &'static ton_abi::Function {
    declare_function! {
        name: "indexBasisCode",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("code", ParamType::Cell)],
    }
}

///Get contract index basis code hash
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `hash: uint256` - Index basic code hash of the contract
///
pub fn index_basis_code_hash() -> &'static ton_abi::Function {
    declare_function! {
        name: "indexBasisCodeHash",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("hash", ParamType::Uint(256))],
    }
}

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

///Get contract index basis
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `indexBasis: address` - Index basis of the contract
///
pub fn resolve_index_basis() -> &'static ton_abi::Function {
    declare_function! {
        name: "indexBCode",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("indexBasis", ParamType::Address)],
    }
}
