use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

/// Returns a certificate address derived from the specified path
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
/// * `path: string` - domain path
///
/// # Outputs
/// * `certificate: address`
pub fn resolve() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_2,
        name: "resolve",
        inputs: vec![
            Param::new("answerId", ParamType::Uint(32)),
            Param::new("path", ParamType::String),
        ],
        outputs: vec![Param::new("certificate", ParamType::Address)],
    }
}
