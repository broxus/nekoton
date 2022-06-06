use crate::nft_index::index_contract::IndexGetInfoOutputs;
use crate::RunLocalSimple;
use anyhow::Result;
use nekoton_abi::{BuildTokenValue, ExecutionContext, TokenValueExt, UnpackAbiPlain};

pub mod index_contract;

#[derive(Copy, Clone)]
pub struct IndexContract<'a>(pub ExecutionContext<'a>);

impl IndexContract<'_> {
    pub fn get_info(&self) -> Result<IndexGetInfoOutputs> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_responsible_simple(index_contract::get_info(), &inputs)?
            .unpack()?;
        Ok(result)
    }
}
