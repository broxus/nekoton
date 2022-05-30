use anyhow::Result;
use nekoton_abi::*;

use crate::tip4_1::collection_contract::NftCodeHashOutputs;
use crate::tip4_1::nft_contract::{ChangeOwnerInputs, GetInfoOutputs};
use crate::RunLocalSimple;

mod collection_contract;
mod nft_contract;

#[derive(Copy, Clone)]
pub struct CollectionContract<'a>(pub ExecutionContext<'a>);

impl CollectionContract<'_> {
    pub fn total_supply(&self) -> Result<u128> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_responsible_simple(collection_contract::total_supply(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }

    pub fn code(&self) -> Result<ton_types::Cell> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_responsible_simple(collection_contract::nft_code(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }

    pub fn code_hash(&self, code: ton_types::Cell) -> Result<ton_types::UInt256> {
        let inputs = [
            0u32.token_value().named("answerId"),
            code.token_value().named("code"),
        ];
        let result: NftCodeHashOutputs = self
            .0
            .run_local_responsible_simple(collection_contract::nft_code_hash(), &inputs)?
            .unpack()?;
        Ok(result.code_hash)
    }

    pub fn nft_address(&self, id: ton_types::UInt256) -> Result<ton_block::MsgAddressInt> {
        let inputs = [
            0u32.token_value().named("answerId"),
            id.token_value().named("id"),
        ];
        let result = self
            .0
            .run_local_responsible_simple(collection_contract::nft_address(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}

#[derive(Copy, Clone)]
pub struct NftContract<'a>(pub ExecutionContext<'a>);

impl NftContract<'_> {
    pub fn get_info(&self) -> Result<GetInfoOutputs> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_responsible_simple(nft_contract::get_info(), &inputs)?
            .unpack()?;
        Ok(result)
    }

    pub fn change_owner(&self, inputs: ChangeOwnerInputs) -> Result<()> {
        self.0
            .run_local_simple(nft_contract::change_owner(), &inputs.pack())?;
        Ok(())
    }

    pub fn change_manager(&self, inputs: ChangeOwnerInputs) -> Result<()> {
        self.0
            .run_local_simple(nft_contract::change_manager(), &inputs.pack())?;
        Ok(())
    }

    pub fn transfer(&self, inputs: ChangeOwnerInputs) -> Result<()> {
        self.0
            .run_local_simple(nft_contract::transfer(), &inputs.pack())?;
        Ok(())
    }
}
