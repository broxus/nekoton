use nekoton_abi::*;
use ton_abi::{Param, ParamType};
use ton_types::UInt256;

use crate::utils::declare_function;

pub const INTERFACE_ID: u32 = 0x1217AAAB;

///Get count of active NFTs for this collection
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `count: uint128` - A count of active NFTs minted by this contract except for burned NFTs
///
pub fn total_supply() -> &'static ton_abi::Function {
    declare_function! {
        name: "rootOwner",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("count", ParamType::Uint(128))],
    }
}

///Get the NFT code
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `code: cell` - NFT code as `TvmCell`
///
pub fn nft_code() -> &'static ton_abi::Function {
    declare_function! {
        name: "nftCode",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("code", ParamType::Cell)],
    }
}

#[derive(Debug, Clone, Copy, KnownParamTypePlain, PackAbiPlain, UnpackAbiPlain)]
pub struct NftCodeHashOutputs {
    #[abi(uint256, name = "codeHash")]
    pub code_hash: UInt256,
}

///Get the NFT code hash
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `codeHash: uint256` - The NFT code hash
///
pub fn nft_code_hash() -> &'static ton_abi::Function {
    declare_function! {
        name: "nftCodeHash",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: NftCodeHashOutputs::param_type(),
    }
}

///Computes NFT address by unique NFT id
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
/// * `id: uint256` - Unique NFT id
///
/// # Outputs
/// * `nft: address` - Address of NFT contract
///
pub fn nft_address() -> &'static ton_abi::Function {
    declare_function! {
        name: "nftCodeHash",
        inputs: vec![
            Param::new("answerId", ParamType::Uint(32)),
            Param::new("id", ParamType::Uint(256))
        ],
        outputs: vec![Param::new("nft", ParamType::Address)],
    }
}
