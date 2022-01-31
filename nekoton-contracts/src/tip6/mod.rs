use anyhow::Result;
use nekoton_abi::*;

use crate::RunLocalSimple;

pub mod sid;

#[derive(Copy, Clone)]
pub struct SidContract<'a>(pub ExecutionContext<'a>);

impl SidContract<'_> {
    pub fn supports_interface(&mut self, interface: u32) -> Result<bool> {
        let inputs = [
            0u32.token_value().named("answerId"),
            ton_abi::Token::new(
                "interfaceID",
                ton_abi::TokenValue::FixedBytes(interface.to_be_bytes().to_vec()),
            ),
        ];
        let result = self
            .0
            .run_local_simple(sid::supports_interface(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}
