use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

/// A contract that is compliant with TIP4 shall implement the following interface
///
/// # Type
/// Responsible internal method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `name: string`
///
pub fn supports_interface() -> &'static ton_abi::Function {
    declare_function! {
        name: "supportsInterface",
        inputs: vec![
            Param::new("answerId", ParamType::Uint(32)),
            Param::new("interfaceID", ParamType::Uint(32))
        ],
        outputs: vec![Param::new("name", ParamType::String)],
    }
}
