use anyhow::Result;
use nekoton_abi::*;

use crate::RunLocalSimple;

pub mod root_token_contract;
pub mod token_wallet_contract;

#[derive(Copy, Clone)]
pub struct RootTokenContract<'a>(pub ExecutionContext<'a>);

impl RootTokenContract<'_> {
    pub fn get_version(&self) -> Result<u32> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_simple(root_token_contract::get_version(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }

    pub fn get_details(&self) -> Result<root_token_contract::RootTokenContractDetails> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_simple(root_token_contract::get_details(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }

    pub fn get_wallet_address(
        &self,
        owner: ton_block::MsgAddressInt,
    ) -> Result<ton_block::MsgAddressInt> {
        let inputs = [
            0u32.token_value().named("answerId"),
            owner.token_value().named("owner"),
        ];
        let result = self
            .0
            .run_local_simple(root_token_contract::get_wallet_address(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}

pub struct TokenWalletContract<'a>(pub ExecutionContext<'a>);

impl TokenWalletContract<'_> {
    pub fn get_code_hash(&self) -> Result<ton_types::UInt256> {
        match &self.0.account_stuff.storage.state {
            ton_block::AccountState::AccountActive { state_init, .. } => {
                let code = state_init.code.as_ref().ok_or(WalletNotDeployed)?;
                Ok(code.repr_hash())
            }
            _ => Err(WalletNotDeployed.into()),
        }
    }

    pub fn get_version(&self) -> Result<u32> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_simple(token_wallet_contract::get_version(), &inputs)?
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

    pub fn get_details(&self) -> Result<token_wallet_contract::TokenWalletDetails> {
        let inputs = [0u32.token_value().named("answerId")];
        let result = self
            .0
            .run_local_simple(token_wallet_contract::get_details(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Token wallet not deployed")]
struct WalletNotDeployed;
