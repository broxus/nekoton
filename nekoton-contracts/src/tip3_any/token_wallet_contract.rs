use nekoton_abi::num_bigint::BigUint;
use nekoton_abi::ExecutionContext;

use super::{Tip3Error, TokenWalletDetails, TokenWalletVersion};
use crate::{old_tip3, tip3, tip3_1, tip6};

pub struct TokenWalletContractState<'a>(pub ExecutionContext<'a>);

impl<'a> TokenWalletContractState<'a> {
    pub fn get_code_hash(&self) -> anyhow::Result<ton_types::UInt256> {
        match &self.0.account_stuff.storage.state {
            ton_block::AccountState::AccountActive { state_init, .. } => {
                let code = state_init
                    .code
                    .as_ref()
                    .ok_or(Tip3Error::WalletNotDeployed)?;
                Ok(code.repr_hash())
            }
            _ => Err(Tip3Error::WalletNotDeployed.into()),
        }
    }

    pub fn get_balance(&self, version: TokenWalletVersion) -> anyhow::Result<BigUint> {
        match version {
            TokenWalletVersion::OldTip3v4 => old_tip3::TokenWalletContract(self.0).balance(),
            TokenWalletVersion::Tip3 => tip3::TokenWalletContract(self.0).balance(),
        }
    }

    pub fn get_details(&self, version: TokenWalletVersion) -> anyhow::Result<TokenWalletDetails> {
        Ok(match version {
            TokenWalletVersion::OldTip3v4 => {
                let details = old_tip3::TokenWalletContract(self.0).get_details()?;

                TokenWalletDetails {
                    root_address: details.root_address,
                    owner_address: details.owner_address,
                    balance: details.balance,
                }
            }
            TokenWalletVersion::Tip3 => {
                let token_wallet = tip3::TokenWalletContract(self.0);
                let root_address = token_wallet.root()?;
                let balance = token_wallet.balance()?;

                let token_wallet = tip3_1::TokenWalletContract(self.0);
                let owner_address = token_wallet.owner()?;

                TokenWalletDetails {
                    root_address,
                    owner_address,
                    balance,
                }
            }
        })
    }

    pub fn get_version(&self) -> anyhow::Result<TokenWalletVersion> {
        if let Ok(true) = tip6::SidContract(self.0).supports_interfaces(&[
            tip3::token_wallet_contract::INTERFACE_ID,
            tip3_1::token_wallet_contract::INTERFACE_ID,
        ]) {
            return Ok(TokenWalletVersion::Tip3);
        }

        match old_tip3::TokenWalletContract(self.0).get_version()? {
            4 => Ok(TokenWalletVersion::OldTip3v4),
            _ => Err(Tip3Error::UnknownVersion.into()),
        }
    }
}
