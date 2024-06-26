use crate::utils::declare_function;
use ton_abi::{Param, ParamType};

pub const INTERFACE_ID: u32 = 0x244a5200;

/// Build url to get metadata for NFT.
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
/// * `part: cell` - encoded URL part
///
/// # Outputs
/// * `nftUrl: string` - NFT metadata URL
pub fn get_nft_url() -> &'static ton_abi::Function {
    declare_function! {
        name: "getNftUrl",
        inputs: vec![
            Param::new("answerId", ParamType::Uint(32)),
            Param::new("part", ParamType::Cell),
        ],
        outputs: vec![Param::new("nftUrl", ParamType::String)]
    }
}
