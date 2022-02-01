use anyhow::Result;
use nekoton_abi::*;

use crate::RunLocalSimple;

pub mod root_token_contract;
pub mod token_wallet_contract;

#[derive(Copy, Clone)]
pub struct RootTokenContract<'a>(pub ExecutionContext<'a>);

impl RootTokenContract<'_> {
    pub fn root_owner(&self) -> Result<ton_block::MsgAddressInt> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_responsible_simple(root_token_contract::root_owner(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }

    pub fn wallet_of(&self, owner: ton_block::MsgAddressInt) -> Result<ton_block::MsgAddressInt> {
        let inputs = [
            0u32.token_value().named("answerId"),
            owner.token_value().named("owner"),
        ];
        let result = self
            .0
            .run_local_responsible_simple(root_token_contract::wallet_of(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}

#[derive(Copy, Clone)]
pub struct TokenWalletContract<'a>(pub ExecutionContext<'a>);

impl TokenWalletContract<'_> {
    pub fn owner(&self) -> Result<ton_block::MsgAddressInt> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_responsible_simple(token_wallet_contract::owner(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}
