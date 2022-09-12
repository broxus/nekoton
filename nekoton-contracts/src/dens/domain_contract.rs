use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

/// Returns optional certificate record
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
/// * `key: uint32` - record id
///
/// # Outputs
/// * `value: optional(cell)`
pub fn query() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_2,
        name: "query",
        inputs: vec![
            Param::new("answerId", ParamType::Uint(32)),
            Param::new("key", ParamType::Uint(32)),
        ],
        outputs: vec![Param::new("value", ParamType::Optional(Box::new(ParamType::Cell)))],
    }
}

/// Returns full domain path
///
/// NOTE: Can also be used for DeNS root contract
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `path: string`
pub fn get_path() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_2,
        name: "getPath",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("path", ParamType::String)],
    }
}
