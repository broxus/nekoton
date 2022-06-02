use crate::utils::declare_function;
use ton_abi::{Param, ParamType};

pub const INTERFACE_ID: u32 = 0x24D7D5F5;

///Get NFT metadata in JSON format
///
/// # Type
/// Responsible getter method
///
/// # Outputs
/// * `json: string` - The JSON string with metadata
///
pub fn get_json() -> &'static ton_abi::Function {
    declare_function! {
        name: "getJson",
        inputs: vec![],
        outputs: vec![Param::new("json", ParamType::String)],
    }
}
