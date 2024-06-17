use crate::utils::declare_function;
use ton_abi::{Param, ParamType};

pub const INTERFACE_ID: u32 = 0x7239d7b1;

/// Get URL parts identifying the NFT.
///
/// # Type
/// Responsible getter method
///
/// # Outputs
/// * `part: cell` - encoded URL part
pub fn get_url_parts() -> &'static ton_abi::Function {
    declare_function! {
        name: "getUrlParts",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("part", ParamType::Cell)]
    }
}
