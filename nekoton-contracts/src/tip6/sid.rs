use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

pub const TIP6_SID_INTERFACE_ID: u32 = 0x3204ec29;

/// A contract that is compliant with TIP6 shall implement the following interface
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
/// * `interfaceID: bytes4` - interface ID
///
/// # Outputs
/// * `name: string`
///
pub fn supports_interface() -> &'static ton_abi::Function {
    declare_function! {
        name: "supportsInterface",
        inputs: vec![
            Param::new("answerId", ParamType::Uint(32)),
            Param::new("interfaceID", ParamType::FixedBytes(4))
        ],
        outputs: vec![Param::new("supports", ParamType::Bool)],
    }
}
