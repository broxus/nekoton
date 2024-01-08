use nekoton_abi::ExecutionContext;
use ton_block::MsgAddressInt;

use super::{RootTokenContractDetails, Tip3Error, TokenWalletVersion};
use crate::{old_tip3, tip3, tip3_1, tip6};

pub struct RootTokenContractState<'a>(pub ExecutionContext<'a>);

impl RootTokenContractState<'_> {
    /// Calculates token wallet address
    pub fn get_wallet_address(
        &self,
        version: TokenWalletVersion,
        owner: &MsgAddressInt,
    ) -> anyhow::Result<MsgAddressInt> {
        match version {
            TokenWalletVersion::OldTip3v4 => {
                old_tip3::RootTokenContract(self.0).get_wallet_address(owner.clone())
            }
            TokenWalletVersion::Tip3 => tip3_1::RootTokenContract(self.0).wallet_of(owner.clone()),
        }
    }

    /// Tries to guess version and retrieve details
    pub fn guess_details(&self) -> anyhow::Result<RootTokenContractDetails> {
        if let Ok(true) = tip6::SidContract(self.0).supports_interfaces(&[
            tip3::root_token_contract::INTERFACE_ID,
            tip3_1::root_token_contract::INTERFACE_ID,
        ]) {
            return self.get_details(TokenWalletVersion::Tip3);
        }

        let version = match old_tip3::RootTokenContract(self.0).get_version()? {
            4 => TokenWalletVersion::OldTip3v4,
            _ => anyhow::bail!(Tip3Error::UnknownVersion),
        };

        self.get_details(version)
    }

    /// Retrieve details using specified version
    pub fn get_details(
        &self,
        version: TokenWalletVersion,
    ) -> anyhow::Result<RootTokenContractDetails> {
        Ok(match version {
            TokenWalletVersion::OldTip3v4 => {
                let details = old_tip3::RootTokenContract(self.0).get_details()?;

                RootTokenContractDetails {
                    version,
                    name: details.name,
                    symbol: details.symbol,
                    decimals: details.decimals,
                    owner_address: details.root_owner_address,
                    total_supply: details.total_supply,
                }
            }
            TokenWalletVersion::Tip3 => {
                let root_contract = tip3::RootTokenContract(self.0);
                let name = root_contract.name()?;
                let symbol = root_contract.symbol()?;
                let decimals = root_contract.decimals()?;
                let total_supply = root_contract.total_supply()?;

                let root_contract = tip3_1::RootTokenContract(self.0);
                let owner_address = root_contract.root_owner()?;

                RootTokenContractDetails {
                    version,
                    name,
                    symbol,
                    decimals,
                    owner_address,
                    total_supply,
                }
            }
        })
    }
}
