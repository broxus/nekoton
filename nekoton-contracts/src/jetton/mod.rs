use nekoton_abi::num_bigint::BigUint;
use nekoton_abi::{ExecutionContext, StackItem};
use thiserror::Error;
use ton_block::Serializable;
use ton_types::SliceData;

pub use root_token_contract::JettonRootData;
pub use token_wallet_contract::JettonWalletData;

mod root_token_contract;
mod token_wallet_contract;

#[derive(Copy, Clone)]
pub struct RootTokenContract<'a>(pub ExecutionContext<'a>);

pub const GET_JETTON_DATA: &str = "get_jetton_data";
pub const GET_WALLET_DATA: &str = "get_wallet_data";
pub const GET_WALLET_ADDRESS: &str = "get_wallet_address";

impl RootTokenContract<'_> {
    pub fn name(&self) -> anyhow::Result<String> {
        let result = self.0.run_getter(GET_JETTON_DATA, &[])?;

        let data = root_token_contract::get_jetton_data(result)?;
        data.content.name.ok_or(JettonDataError::NotExist.into())
    }

    pub fn symbol(&self) -> anyhow::Result<String> {
        let result = self.0.run_getter(GET_JETTON_DATA, &[])?;

        let data = root_token_contract::get_jetton_data(result)?;
        data.content.symbol.ok_or(JettonDataError::NotExist.into())
    }

    pub fn decimals(&self) -> anyhow::Result<u8> {
        let result = self.0.run_getter(GET_JETTON_DATA, &[])?;

        let data = root_token_contract::get_jetton_data(result)?;
        data.content
            .decimals
            .ok_or(JettonDataError::NotExist.into())
    }

    pub fn total_supply(&self) -> anyhow::Result<BigUint> {
        let result = self.0.run_getter(GET_JETTON_DATA, &[])?;

        let data = root_token_contract::get_jetton_data(result)?;
        Ok(data.total_supply)
    }

    pub fn wallet_code(&self) -> anyhow::Result<ton_types::Cell> {
        let result = self.0.run_getter(GET_JETTON_DATA, &[])?;

        let data = root_token_contract::get_jetton_data(result)?;
        Ok(data.wallet_code)
    }

    pub fn get_wallet_address(
        &self,
        owner: &ton_block::MsgAddressInt,
    ) -> anyhow::Result<ton_block::MsgAddressInt> {
        let arg = StackItem::Slice(SliceData::load_cell(owner.serialize()?)?);
        let result = self.0.run_getter(GET_WALLET_ADDRESS, &[arg])?;

        let address = root_token_contract::get_wallet_address(result)?;
        Ok(address)
    }

    pub fn get_details(&self) -> anyhow::Result<JettonRootData> {
        let result = self.0.run_getter(GET_JETTON_DATA, &[])?;

        let data = root_token_contract::get_jetton_data(result)?;
        Ok(data)
    }
}

#[derive(Copy, Clone)]
pub struct TokenWalletContract<'a>(pub ExecutionContext<'a>);

impl<'a> TokenWalletContract<'a> {
    pub fn root(&self) -> anyhow::Result<ton_block::MsgAddressInt> {
        let result = self.0.run_getter(GET_WALLET_DATA, &[])?;

        let data = token_wallet_contract::get_wallet_data(result)?;
        Ok(data.root_address)
    }

    pub fn balance(&self) -> anyhow::Result<BigUint> {
        let result = self.0.run_getter(GET_WALLET_DATA, &[])?;

        let data = token_wallet_contract::get_wallet_data(result)?;
        Ok(data.balance)
    }

    pub fn get_details(&self) -> anyhow::Result<JettonWalletData> {
        let result = self.0.run_getter(GET_WALLET_DATA, &[])?;

        let data = token_wallet_contract::get_wallet_data(result)?;
        Ok(data)
    }
}

#[derive(Error, Debug)]
pub enum JettonDataError {
    #[error("Not exist")]
    NotExist,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use nekoton_abi::num_bigint::BigUint;
    use nekoton_abi::num_traits::FromPrimitive;
    use nekoton_abi::ExecutionContext;
    use nekoton_utils::SimpleClock;
    use ton_block::MsgAddressInt;

    use crate::jetton;

    #[test]
    fn root_token_contract() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("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").unwrap().as_slice()).unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::RootTokenContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let name = contract.name()?;
        assert_eq!(name, "TonUP");

        let symbol = contract.symbol()?;
        assert_eq!(symbol, "UP");

        let decimals = contract.decimals()?;
        assert_eq!(decimals, 9);

        let total_supply = contract.total_supply()?;
        assert_eq!(total_supply, BigUint::from_u128(56837335582855498).unwrap());

        let wallet_code = contract.wallet_code()?;
        let expected_code = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6cckECEQEAAyMAART/APSkE/S88sgLAQIBYgIDAgLMBAUAG6D2BdqJofQB9IH0gahhAgHUBgcCASAICQDDCDHAJJfBOAB0NMDAXGwlRNfA/AM4PpA+kAx+gAxcdch+gAx+gAwc6m0AALTH4IQD4p+pVIgupUxNFnwCeCCEBeNRRlSILqWMUREA/AK4DWCEFlfB7y6k1nwC+BfBIQP8vCAAET6RDBwuvLhTYAIBIAoLAIPUAQa5D2omh9AH0gfSBqGAJpj8EIC8aijKkQXUEIPe7L7wndCVj5cWLpn5j9ABgJ0CgR5CgCfQEsZ4sA54tmZPaqQB8VA9M/+gD6QCHwAe1E0PoA+kD6QNQwUTahUirHBfLiwSjC//LiwlQ0QnBUIBNUFAPIUAT6AljPFgHPFszJIsjLARL0APQAywDJIPkAcHTIywLKB8v/ydAE+kD0BDH6ACDXScIA8uLEd4AYyMsFUAjPFnD6AhfLaxPMgMAgEgDQ4AnoIQF41FGcjLHxnLP1AH+gIizxZQBs8WJfoCUAPPFslQBcwjkXKRceJQCKgToIIJycOAoBS88uLFBMmAQPsAECPIUAT6AljPFgHPFszJ7VQC9ztRND6APpA+kDUMAjTP/oAUVGgBfpA+kBTW8cFVHNtcFQgE1QUA8hQBPoCWM8WAc8WzMkiyMsBEvQA9ADLAMn5AHB0yMsCygfL/8nQUA3HBRyx8uLDCvoAUaihggiYloBmtgihggiYloCgGKEnlxBJEDg3XwTjDSXXCwGAPEADXO1E0PoA+kD6QNQwB9M/+gD6QDBRUaFSSccF8uLBJ8L/8uLCBYIJMS0AoBa88uLDghB73ZfeyMsfFcs/UAP6AiLPFgHPFslxgBjIywUkzxZw+gLLaszJgED7AEATyFAE+gJYzxYBzxbMye1UgAHBSeaAYoYIQc2LQnMjLH1Iwyz9Y+gJQB88WUAfPFslxgBDIywUkzxZQBvoCFctqFMzJcfsAECQQIwB8wwAjwgCwjiGCENUydttwgBDIywVQCM8WUAT6AhbLahLLHxLLP8ly+wCTNWwh4gPIUAT6AljPFgHPFszJ7VSV6u3X")?.as_slice())?;
        assert_eq!(wallet_code, expected_code);

        Ok(())
    }

    #[test]
    fn wallet_token_contract() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgECEwEAA6kAAm6ADhM4pof2jbUfk8bYdFfLChAB6cUG0z98g+xOrlf4LCzkTQz7BmMVjoAAAVA6z3tMKgC1Y0MmAgEBj0dzWUAIAc+mHGAhdljL3SZo8QcvtpqlV+kMrO8+wlbsMF9hxLGVACvaf0JMrv6BOvPpAgee08uQM/uRpUd//fhA7Nm8twzvYAIBFP8A9KQT9LzyyAsDAgFiBQQAG6D2BdqJofQB9IH0gahhAgLMEAYCASAIBwCD1AEGuQ9qJofQB9IH0gahgCaY/BCAvGooypEF1BCD3uy+8J3QlY+XFi6Z+Y/QAYCdAoEeQoAn0BLGeLAOeLZmT2qkAgEgDgkCASALCgDXO1E0PoA+kD6QNQwB9M/+gD6QDBRUaFSSccF8uLBJ8L/8uLCBYIJMS0AoBa88uLDghB73ZfeyMsfFcs/UAP6AiLPFgHPFslxgBjIywUkzxZw+gLLaszJgED7AEATyFAE+gJYzxYBzxbMye1UgAvc7UTQ+gD6QPpA1DAI0z/6AFFRoAX6QPpAU1vHBVRzbXBUIBNUFAPIUAT6AljPFgHPFszJIsjLARL0APQAywDJ+QBwdMjLAsoHy//J0FANxwUcsfLiwwr6AFGooYIImJaAZrYIoYIImJaAoBihJ5cQSRA4N18E4w0l1wsBgDQwAfMMAI8IAsI4hghDVMnbbcIAQyMsFUAjPFlAE+gIWy2oSyx8Syz/JcvsAkzVsIeIDyFAE+gJYzxYBzxbMye1UAHBSeaAYoYIQc2LQnMjLH1Iwyz9Y+gJQB88WUAfPFslxgBDIywUkzxZQBvoCFctqFMzJcfsAECQQIwHxUD0z/6APpAIfAB7UTQ+gD6QPpA1DBRNqFSKscF8uLBKML/8uLCVDRCcFQgE1QUA8hQBPoCWM8WAc8WzMkiyMsBEvQA9ADLAMkg+QBwdMjLAsoHy//J0AT6QPQEMfoAINdJwgDy4sR3gBjIywVQCM8WcPoCF8trE8yA8AnoIQF41FGcjLHxnLP1AH+gIizxZQBs8WJfoCUAPPFslQBcwjkXKRceJQCKgToIIJycOAoBS88uLFBMmAQPsAECPIUAT6AljPFgHPFszJ7VQCAdQSEQARPpEMHC68uFNgAMMIMcAkl8E4AHQ0wMBcbCVE18D8Azg+kD6QDH6ADFx1yH6ADH6ADBzqbQAAtMfghAPin6lUiC6lTE0WfAJ4IIQF41FGVIgupYxREQD8ArgNYIQWV8HvLqTWfAL4F8EhA/y8IA==").unwrap().as_slice()).unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::TokenWalletContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let balance = contract.balance()?;
        assert_eq!(balance, BigUint::from_u128(2000000000).unwrap());

        let root = contract.root()?;
        assert_eq!(
            root,
            MsgAddressInt::from_str(
                "0:af69fd0932bbfa04ebcfa4081e7b4f2e40cfee46951dfff7e103b366f2dc33bd"
            )?
        );

        Ok(())
    }

    #[test]
    fn wallet_address() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("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").unwrap().as_slice()).unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::RootTokenContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let owner = nekoton_utils::unpack_std_smc_addr(
            "EQC-D0YPvNUq92FeG7_ZGFQY-L-lZ0wayn8arc4AKElbSo6v",
            true,
        )?;

        let expected = nekoton_utils::unpack_std_smc_addr(
            "EQBWqBJJQriSjGTOBXPPSZjZoTnESO3RqPLrO6enXSq--yes",
            true,
        )?;

        let address = contract.get_wallet_address(&owner)?;
        assert_eq!(address, expected);

        Ok(())
    }
}
