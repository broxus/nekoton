use nekoton_abi::*;
use ton_abi::{Param, ParamType};
use ton_block::MsgAddressInt;

use crate::utils::declare_function;

#[derive(Debug, Clone, KnownParamTypePlain, PackAbiPlain, UnpackAbiPlain)]
pub struct IndexGetInfoOutputs {
    #[abi(address)]
    pub collection: MsgAddressInt,
    #[abi(address)]
    pub owner: MsgAddressInt,
    #[abi(address)]
    pub nft: MsgAddressInt,
}

///Get NFT info
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `collection: address` - Collection token contract address
/// * `owner: address` - Token owner contract address
/// * `nft: address` - Token contract address
///
pub fn get_info() -> &'static ton_abi::Function {
    declare_function! {
        name: "getInfo",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: IndexGetInfoOutputs::param_type(),
    }
}
