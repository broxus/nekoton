use anyhow::Result;
use nekoton_abi::*;

use crate::RunLocalSimple;

pub mod root_token_contract;
pub mod token_wallet_contract;

#[derive(Copy, Clone)]
pub struct RootTokenContract<'a>(pub ExecutionContext<'a>);

impl RootTokenContract<'_> {
    pub fn name(&self) -> Result<String> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_simple(root_token_contract::name(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }

    pub fn symbol(&self) -> Result<String> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_simple(root_token_contract::symbol(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }

    pub fn decimals(&self) -> Result<u8> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_simple(root_token_contract::decimals(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }

    pub fn total_supply(&self) -> Result<u128> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_simple(root_token_contract::total_supply(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }

    pub fn wallet_code(&self) -> Result<ton_types::Cell> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_simple(root_token_contract::wallet_code(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}

#[derive(Copy, Clone)]
pub struct TokenWalletContract<'a>(pub ExecutionContext<'a>);

impl<'a> TokenWalletContract<'a> {
    pub fn root(&self) -> Result<ton_block::MsgAddressInt> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_simple(token_wallet_contract::root(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }

    pub fn balance(&self) -> Result<u128> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_simple(token_wallet_contract::balance(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}
