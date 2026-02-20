use crate::RunLocalSimple;
use anyhow::Result;
use nekoton_abi::ExecutionContext;
use nekoton_abi::*;

pub mod collection_contract;
pub mod metadata_contract;

#[derive(Copy, Clone)]
pub struct MetadataContract<'a>(pub ExecutionContext<'a>);

impl MetadataContract<'_> {
    pub fn get_url_parts(&self) -> Result<ton_types::Cell> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_responsible_simple(metadata_contract::get_url_parts(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}

#[derive(Copy, Clone)]
pub struct CollectionContract<'a>(pub ExecutionContext<'a>);

impl CollectionContract<'_> {
    pub fn get_nft_url(&self, part: ton_types::Cell) -> Result<String> {
        let inputs = [
            0u32.token_value().named("answerId"),
            part.token_value().named("part"),
        ];
        let result = self
            .0
            .run_local_responsible_simple(collection_contract::get_nft_url(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }

    pub fn get_collection_url(&self) -> Result<String> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_responsible_simple(collection_contract::get_collection_url(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}
