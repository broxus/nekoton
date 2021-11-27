use num_bigint::BigUint;
use ton_block::MsgAddressInt;
use ton_types::UInt256;

use nekoton_abi::*;

#[derive(UnpackAbi)]
pub struct BriefRootTokenContractDetails {
    #[abi]
    pub name: String,
    #[abi]
    pub symbol: String,
    #[abi(uint8)]
    pub decimals: u8,
    #[abi(with = "uint256_bytes")]
    pub root_public_key: UInt256,
    #[abi(address)]
    pub root_owner_address: MsgAddressInt,
    #[abi(with = "uint128_number")]
    pub total_supply: BigUint,
}

#[derive(UnpackAbi)]
pub struct TonTokenWalletDetails {
    #[abi(address)]
    pub root_address: MsgAddressInt,
    #[abi(with = "uint256_bytes")]
    pub wallet_public_key: UInt256,
    #[abi(address)]
    pub owner_address: MsgAddressInt,
    #[abi(name = "balance", with = "uint128_number")]
    pub balance: BigUint,
    /*#[abi(address)]
    _receive_callback: MsgAddressInt,
    #[abi(address)]
    _bounced_callback: MsgAddressInt,
    #[abi(bool)]
    _allow_non_notifiable: bool,*/
}

#[derive(UnpackAbiPlain)]
pub struct TonTokenWalletBalance {
    #[abi(name = "value0", with = "uint128_number")]
    pub balance: BigUint,
}
