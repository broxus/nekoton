pub mod collection_contract;
pub mod nft_contract;

use crate::RunLocalSimple;
use anyhow::Result;
use nekoton_abi::ExecutionContext;
use nekoton_abi::*;
use ton_types::Cell;

#[derive(Copy, Clone)]
pub struct CollectionContract<'a>(pub ExecutionContext<'a>);

impl CollectionContract<'_> {
    pub fn index_code(&self) -> Result<Cell> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_responsible_simple(collection_contract::index_code(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}
