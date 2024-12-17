use nekoton_abi::num_bigint::BigUint;
use nekoton_abi::{ExecutionContext, StackItem};
use ton_block::{AccountState, Deserializable, Serializable};
use ton_types::{CellType, SliceData, UInt256};

pub use root_token_contract::JettonRootData;
pub use token_wallet_contract::JettonWalletData;

use crate::wallets;

mod root_token_contract;
mod token_wallet_contract;

#[derive(Copy, Clone)]
pub struct RootTokenContract<'a>(pub ExecutionContext<'a>);

pub const GET_JETTON_DATA: &str = "get_jetton_data";
pub const GET_WALLET_DATA: &str = "get_wallet_data";
pub const GET_WALLET_ADDRESS: &str = "get_wallet_address";

impl RootTokenContract<'_> {
    pub fn name(&self) -> anyhow::Result<Option<String>> {
        let result = self.0.run_getter(GET_JETTON_DATA, &[])?;

        let data = root_token_contract::get_jetton_data(result)?;
        Ok(data.content.name)
    }

    pub fn symbol(&self) -> anyhow::Result<Option<String>> {
        let result = self.0.run_getter(GET_JETTON_DATA, &[])?;

        let data = root_token_contract::get_jetton_data(result)?;
        Ok(data.content.symbol)
    }

    pub fn decimals(&self) -> anyhow::Result<Option<u8>> {
        let result = self.0.run_getter(GET_JETTON_DATA, &[])?;

        let data = root_token_contract::get_jetton_data(result)?;
        Ok(data.content.decimals)
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

pub fn update_library_cell(state: &mut AccountState) -> anyhow::Result<()> {
    if let AccountState::AccountActive { ref mut state_init } = state {
        if let Some(cell) = &state_init.code {
            if cell.cell_type() == CellType::LibraryReference {
                let mut slice_data = SliceData::load_cell(cell.clone())?;

                // Read Library Cell Tag
                let tag = slice_data.get_next_byte()?;
                assert_eq!(tag, 2);

                // Read Code Hash
                let mut hash = UInt256::default();
                hash.read_from(&mut slice_data)?;

                if let Some(cell) = wallets::code::get_jetton_library_cell(&hash) {
                    state_init.set_code(cell.clone());
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use nekoton_abi::num_bigint::BigUint;
    use nekoton_abi::num_traits::{FromPrimitive, ToPrimitive};
    use nekoton_abi::ExecutionContext;
    use nekoton_utils::SimpleClock;
    use ton_block::MsgAddressInt;

    use crate::jetton;

    #[test]
    fn usdt_root_token_contract() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("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").unwrap().as_slice()).unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::RootTokenContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let total_supply = contract.total_supply()?;
        assert_eq!(total_supply, BigUint::from_u128(1229976002510000).unwrap());

        Ok(())
    }

    #[test]
    fn tonup_root_token_contract() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgECLwEAB4YAAm6AFe0/oSZXf0CdefSBA89p5cgZ/cjSo7/+/CB2bN5bhnekvRsDhnIRltAAAW6YCV7CEiEatKumIgECUXye1BbWVRSoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABEwIBFP8A9KQT9LzyyAsDAgFiBQQAG6D2BdqJofQB9IH0gahhAgLMEAYCASAIBwCD1AEGuQ9qJofQB9IH0gahgCaY/BCAvGooypEF1BCD3uy+8J3QlY+XFi6Z+Y/QAYCdAoEeQoAn0BLGeLAOeLZmT2qkAgEgDgkCASALCgDXO1E0PoA+kD6QNQwB9M/+gD6QDBRUaFSSccF8uLBJ8L/8uLCBYIJMS0AoBa88uLDghB73ZfeyMsfFcs/UAP6AiLPFgHPFslxgBjIywUkzxZw+gLLaszJgED7AEATyFAE+gJYzxYBzxbMye1UgAvc7UTQ+gD6QPpA1DAI0z/6AFFRoAX6QPpAU1vHBVRzbXBUIBNUFAPIUAT6AljPFgHPFszJIsjLARL0APQAywDJ+QBwdMjLAsoHy//J0FANxwUcsfLiwwr6AFGooYIImJaAZrYIoYIImJaAoBihJ5cQSRA4N18E4w0l1wsBgDQwAfMMAI8IAsI4hghDVMnbbcIAQyMsFUAjPFlAE+gIWy2oSyx8Syz/JcvsAkzVsIeIDyFAE+gJYzxYBzxbMye1UAHBSeaAYoYIQc2LQnMjLH1Iwyz9Y+gJQB88WUAfPFslxgBDIywUkzxZQBvoCFctqFMzJcfsAECQQIwHxUD0z/6APpAIfAB7UTQ+gD6QPpA1DBRNqFSKscF8uLBKML/8uLCVDRCcFQgE1QUA8hQBPoCWM8WAc8WzMkiyMsBEvQA9ADLAMkg+QBwdMjLAsoHy//J0AT6QPQEMfoAINdJwgDy4sR3gBjIywVQCM8WcPoCF8trE8yA8AnoIQF41FGcjLHxnLP1AH+gIizxZQBs8WJfoCUAPPFslQBcwjkXKRceJQCKgToIIJycOAoBS88uLFBMmAQPsAECPIUAT6AljPFgHPFszJ7VQCAdQSEQARPpEMHC68uFNgAMMIMcAkl8E4AHQ0wMBcbCVE18D8Azg+kD6QDH6ADFx1yH6ADH6ADBzqbQAAtMfghAPin6lUiC6lTE0WfAJ4IIQF41FGVIgupYxREQD8ArgNYIQWV8HvLqTWfAL4F8EhA/y8IAEDAMAUAgEgIBUCASAbFgIBIBkXAUG/XQH6XjwGkBxFBGxrLdzqWvdk/qDu1yoQ1ATyMSzrJH0YAAQAOQFBv1II3vRvWh1Pnc5mqzCfSoUTBfFm+R73nZI+9Y40+aIJGgBEACRVUCBpcyB0aGUgbmF0aXZlIHRva2VuIG9mIFRvblVQLgIBIB4cAUG/btT5QqeEjOLLBmt3oRKMah/4xD9Dii3OJGErqf+riwMdAAYAVVABQb9FRqb/4bec/dhrrT24dDE9zeL7BeanSqfzVS2WF8edEx8ADABUb25VUAFDv/CC62Y7V6ABkvSmrEZyiN8t/t252hvuKPZSHIvr0h8ewCEAtABodHRwczovL3B1YmxpYy1taWNyb2Nvc20uczMtYXAtc291dGhlYXN0LTEuYW1hem9uYXdzLmNvbS9kcm9wc2hhcmUvMTcwMjU0MzYyOS9VUC1pY29uLnBuZwEU/wD0pBP0vPLICyMCAWInJAIDemAmJQAfrxb2omh9AH0gamoYP6qQQAB9rbz2omh9AH0gamoYNhj8FAC4KhAJqgoB5CgCfQEsZ4sA54tmZJFkZYCJegB6AGWAZPyAODpkZYFlA+X/5OhAAgLMKSgAk7XwUIgG4KhAJqgoB5CgCfQEsZ4sA54tmZJFkZYCJegB6AGWAZJB8gDg6ZGWBZQPl/+ToO8AMZGWCrGeLKAJ9AQnltYlmZmS4/YBAvHZBjgEkvgfAA6GmBgLjYSS+B8H0gfSAY/QAYuOuQ/QAY/QAYAWmP6Z/2omh9AH0gamoYQAqpOF1HGZqamxsommOC+XAkgX0gfQBqGBBoQDBrkP0AGBKIGigheAUKUCgZ5CgCfQEsZ4tmZmT2qnBBCD3uy+8pOF1xgULSoBpoIQLHa5c1JwuuMCNTc3I8ADjhozUDXHBfLgSQP6QDBZyFAE+gJYzxbMzMntVOA1AsAEjhhRJMcF8uBJ1DBDAMhQBPoCWM8WzMzJ7VTgXwWED/LwKwH+Nl8DggiYloAVoBW88uBLAvpA0wAwlcghzxbJkW3ighDRc1QAcIAYyMsFUAXPFiT6AhTLahPLHxTLPyP6RDBwuo4z+ChEA3BUIBNUFAPIUAT6AljPFgHPFszJIsjLARL0APQAywDJ+QBwdMjLAsoHy//J0M8WlmwicAHLAeL0ACwACsmAQPsAAcA2NzcB+gD6QPgoVBIGcFQgE1QUA8hQBPoCWM8WAc8WzMkiyMsBEvQA9ADLAMn5AHB0yMsCygfL/8nQUAbHBfLgSqEDRUXIUAT6AljPFszMye1UAfpAMCDXCwHDAJFb4w0uAD6CENUydttwgBDIywVQA88WIvoCEstqyx/LP8mAQvsA").unwrap().as_slice()).unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::RootTokenContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let name = contract.name()?;
        assert_eq!(name.unwrap(), "TonUP");

        let symbol = contract.symbol()?;
        assert_eq!(symbol.unwrap(), "UP");

        let decimals = contract.decimals()?;
        assert_eq!(decimals.unwrap(), 9);

        let total_supply = contract.total_supply()?;
        assert_eq!(total_supply, BigUint::from_u128(56837335582855498).unwrap());

        let wallet_code = contract.wallet_code()?;
        let expected_code = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6cckECEQEAAyMAART/APSkE/S88sgLAQIBYgIDAgLMBAUAG6D2BdqJofQB9IH0gahhAgHUBgcCASAICQDDCDHAJJfBOAB0NMDAXGwlRNfA/AM4PpA+kAx+gAxcdch+gAx+gAwc6m0AALTH4IQD4p+pVIgupUxNFnwCeCCEBeNRRlSILqWMUREA/AK4DWCEFlfB7y6k1nwC+BfBIQP8vCAAET6RDBwuvLhTYAIBIAoLAIPUAQa5D2omh9AH0gfSBqGAJpj8EIC8aijKkQXUEIPe7L7wndCVj5cWLpn5j9ABgJ0CgR5CgCfQEsZ4sA54tmZPaqQB8VA9M/+gD6QCHwAe1E0PoA+kD6QNQwUTahUirHBfLiwSjC//LiwlQ0QnBUIBNUFAPIUAT6AljPFgHPFszJIsjLARL0APQAywDJIPkAcHTIywLKB8v/ydAE+kD0BDH6ACDXScIA8uLEd4AYyMsFUAjPFnD6AhfLaxPMgMAgEgDQ4AnoIQF41FGcjLHxnLP1AH+gIizxZQBs8WJfoCUAPPFslQBcwjkXKRceJQCKgToIIJycOAoBS88uLFBMmAQPsAECPIUAT6AljPFgHPFszJ7VQC9ztRND6APpA+kDUMAjTP/oAUVGgBfpA+kBTW8cFVHNtcFQgE1QUA8hQBPoCWM8WAc8WzMkiyMsBEvQA9ADLAMn5AHB0yMsCygfL/8nQUA3HBRyx8uLDCvoAUaihggiYloBmtgihggiYloCgGKEnlxBJEDg3XwTjDSXXCwGAPEADXO1E0PoA+kD6QNQwB9M/+gD6QDBRUaFSSccF8uLBJ8L/8uLCBYIJMS0AoBa88uLDghB73ZfeyMsfFcs/UAP6AiLPFgHPFslxgBjIywUkzxZw+gLLaszJgED7AEATyFAE+gJYzxYBzxbMye1UgAHBSeaAYoYIQc2LQnMjLH1Iwyz9Y+gJQB88WUAfPFslxgBDIywUkzxZQBvoCFctqFMzJcfsAECQQIwB8wwAjwgCwjiGCENUydttwgBDIywVQCM8WUAT6AhbLahLLHxLLP8ly+wCTNWwh4gPIUAT6AljPFgHPFszJ7VSV6u3X")?.as_slice())?;
        assert_eq!(wallet_code, expected_code);

        let token_address = contract.get_wallet_address(&MsgAddressInt::default())?;
        assert_eq!(
            token_address.to_string(),
            "0:0c6a835483369275c9ae76e7e31d9eda0845368045a8ec2ed78609d96bb0a087"
        );

        Ok(())
    }

    #[test]
    fn usdt_wallet_token_contract() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgEBAwEAqAACbIAXsqVXAuRG6+GFp/25WVl2IsmatSkX0jbrXVjoBOwsnEQNAdiGdFv5kAABdRDp2cQZrn10JgIBAJEFJFfQYxaABHulQdJwYfnHP5r0FXhq3wjit36+D+zzx7bkE76OQgrwAsROplLUCShZxn2kTkyjrdZWWw4ol9ZAosUb+zcNiHf6CEICj0Utek39dAZraCNlF3JZ7QVzRDW+drX9S9XYryt8PWg=").unwrap().as_slice()).unwrap();
        let mut state = nekoton_utils::deserialize_account_stuff(cell)?;

        jetton::update_library_cell(&mut state.storage.state)?;

        let contract = jetton::TokenWalletContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let balance = contract.balance()?;
        assert_eq!(balance.to_u128().unwrap(), 156092097302);

        Ok(())
    }

    #[test]
    fn notcoin_wallet_token_contract() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgEBAwEAqgACbIAX5XxfY9N6rJiyOS4NGQc01nd0dzEnWBk87cdqg9bLTwQNAeCGdH/3UAABdXbIjToZrn5eJgIBAJUHFxcOBj4fBYAfGfo6PQWliRZGmmqpYpA1QxmYkyLZonLf41f59x68XdAAvlWFDxGF2lXm67y4yzC17wYKD9A0guwPkMs1gOsM//IIQgK6KRjIlH6bJa+awbiDNXdUFz5YEvgHo9bmQqFHCVlTlQ==").unwrap().as_slice()).unwrap();
        let mut state = nekoton_utils::deserialize_account_stuff(cell)?;

        jetton::update_library_cell(&mut state.storage.state)?;

        let contract = jetton::TokenWalletContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let balance = contract.balance()?;
        assert_eq!(balance.to_u128().unwrap(), 6499273466060549);

        Ok(())
    }

    #[test]
    fn tonup_wallet_token_contract() -> anyhow::Result<()> {
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

    #[test]
    fn mintless_points_root_token_contract() -> anyhow::Result<()> {
        let cell =
            ton_types::deserialize_tree_of_cells(&mut base64::decode("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").unwrap().as_slice())
                .unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::RootTokenContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let details = contract.get_details()?;
        assert_eq!(details.admin_address, MsgAddressInt::default());

        let owner = nekoton_utils::unpack_std_smc_addr(
            "UQA8aeJrWO-5DZ-1Zs2juDYfT4V_ud2KY8gegMd33gHjeUaF",
            true,
        )?;

        let address = contract.get_wallet_address(&owner)?;
        assert_eq!(
            address,
            MsgAddressInt::from_str(
                "0:3d97d11909a20de878c4400ed241a714065d3a0f4d4f0d60ecaf0dbe11cdd1bc"
            )?
        );

        Ok(())
    }
}
