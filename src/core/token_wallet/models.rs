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
    #[abi(cell, name = "wallet_code")]
    _wallet_code: ton_types::Cell,
    #[abi(with = "uint256_bytes")]
    pub root_public_key: UInt256,
    #[abi(address)]
    pub root_owner_address: MsgAddressInt,
    #[abi(with = "uint128_number")]
    pub total_supply: BigUint,
}

#[derive(UnpackAbi)]
pub struct BriefRootTokenContractDetailsV4 {
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
    #[abi(cell)]
    pub code: ton_types::Cell,
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

#[derive(UnpackAbi)]
pub struct TonTokenWalletDetailsV4 {
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

#[derive(UnpackAbi)]
#[abi(plain)]
pub struct TonEventDecodedData {
    #[abi(address, name = "rootToken")]
    pub root_token: MsgAddressInt,
    #[abi(int8, name = "wid")]
    _wid: i8,
    #[abi(name = "addr", with = "uint256_bytes")]
    _addr: UInt256,
    #[abi(with = "uint128_number")]
    pub tokens: BigUint,
    #[abi(with = "uint160_bytes")]
    pub ethereum_address: [u8; 20],
    #[abi(address, name = "owner_address")]
    _owner_address: MsgAddressInt,
}

#[derive(UnpackAbi)]
#[abi(plain)]
pub struct EthEventDecodedData {
    #[abi(address, name = "rootToken")]
    pub root_token: MsgAddressInt,
    #[abi(with = "uint128_number")]
    pub tokens: BigUint,
    #[abi(int8, name = "wid")]
    _wid: i8,
    #[abi(name = "owner_addr", with = "uint256_bytes")]
    _owner_addr: UInt256,
    #[abi(name = "owner_pubkey", with = "uint256_bytes")]
    _owner_pubkey: UInt256,
    #[abi(address, name = "owner_address")]
    _owner_address: MsgAddressInt,
}

#[derive(UnpackAbi)]
pub struct TonEventInitData {
    #[abi(name = "eventTransaction", with = "uint256_bytes")]
    _event_transaction: UInt256,
    #[abi(uint64, name = "eventTransactionLt")]
    _event_transaction_lt: u64,
    #[abi(uint32, name = "eventTimestamp")]
    _event_timestamp: u32,
    #[abi(uint32, name = "eventIndex")]
    _event_index: u32,
    #[abi(cell, name = "eventData")]
    _event_data: ton_types::Cell,
    #[abi(address, name = "tonEventConfiguration")]
    _ton_event_configuration: MsgAddressInt,
    #[abi(uint16, name = "requiredConfirmations")]
    pub required_confirmations: u16,
    #[abi(uint16, name = "requiredRejects")]
    pub required_rejects: u16,
    #[abi(cell, name = "configurationMeta")]
    _configuration_meta: ton_types::Cell,
}

#[derive(UnpackAbi)]
pub struct EthEventInitData {
    #[abi(name = "eventTransaction", with = "uint256_bytes")]
    _event_transaction: UInt256,
    #[abi(uint32, name = "eventIndex")]
    _event_index: u32,
    #[abi(cell, name = "eventData")]
    _event_data: ton_types::Cell,
    #[abi(uint32, name = "eventBlockNumber")]
    _event_block_number: u32,
    #[abi(name = "eventBlock", with = "uint256_bytes")]
    _event_block: UInt256,
    #[abi(address, name = "ethereumEventConfiguration")]
    _ethereum_event_configuration: MsgAddressInt,
    #[abi(uint16, name = "requiredConfirmations")]
    pub required_confirmations: u16,
    #[abi(uint16, name = "requiredRejects")]
    pub required_rejects: u16,
    #[abi(address, name = "proxyAddress")]
    _proxy_address: MsgAddressInt,
    #[abi(cell, name = "configurationMeta")]
    _configuration_meta: ton_types::Cell,
}

#[derive(UnpackAbi)]
#[abi(plain)]
pub struct TonTokenWalletBalance {
    #[abi(name = "value0", with = "uint128_number")]
    pub balance: BigUint,
}
