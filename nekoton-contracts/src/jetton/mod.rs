use nekoton_abi::num_bigint::BigUint;
use nekoton_abi::{ExecutionContext, StackItem};
use ton_block::Serializable;
use ton_types::SliceData;

pub use root_token_contract::{JettonRootData, JettonRootMeta};
pub use token_wallet_contract::JettonWalletData;

mod root_token_contract;
mod token_wallet_contract;

#[derive(Copy, Clone)]
pub struct RootTokenContract<'a>(pub ExecutionContext<'a>);

pub const GET_JETTON_DATA: &str = "get_jetton_data";
pub const GET_JETTON_META: &str = "get_jetton_meta";
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

    pub fn get_meta(&self) -> anyhow::Result<JettonRootMeta> {
        let result = self.0.run_getter(GET_JETTON_META, &[])?;

        let meta = root_token_contract::get_jetton_meta(result)?;
        Ok(meta)
    }
}

#[derive(Copy, Clone)]
pub struct TokenWalletContract<'a>(pub ExecutionContext<'a>);

impl TokenWalletContract<'_> {
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
