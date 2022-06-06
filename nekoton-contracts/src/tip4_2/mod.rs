use crate::RunLocalSimple;
use anyhow::Result;
use nekoton_abi::ExecutionContext;
use nekoton_abi::*;

pub mod metadata_contract;

#[derive(Copy, Clone)]
pub struct MetadataContract<'a>(pub ExecutionContext<'a>);

impl MetadataContract<'_> {
    pub fn get_json(&self) -> Result<String> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_responsible_simple(metadata_contract::get_json(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}
