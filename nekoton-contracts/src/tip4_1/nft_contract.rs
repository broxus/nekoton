use std::collections::BTreeMap;

use nekoton_abi::*;
use ton_abi::{Param, ParamType};
use ton_block::MsgAddressInt;
use ton_types::{Cell, UInt256};

use crate::utils::declare_function;

pub const INTERFACE_ID: u32 = 0x78084F7E;

#[derive(Debug, Clone, KnownParamTypePlain, PackAbiPlain, UnpackAbiPlain)]
pub struct GetInfoOutputs {
    #[abi(with = "uint256_bytes")]
    pub id: UInt256,
    #[abi(address)]
    pub owner: MsgAddressInt,
    #[abi(address)]
    pub manager: MsgAddressInt,
    #[abi(address)]
    pub collection: MsgAddressInt,
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
/// * `id: uint256` - Unique NFT id
/// * `owner: address` - Address of NFT owner
/// * `manager: address` - Address of NFT manager
/// * `collection: address` - Address of collection smart contract, that mint the NFT
///
pub fn get_info() -> &'static ton_abi::Function {
    declare_function! {
        name: "getInfo",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: GetInfoOutputs::param_type(),
    }
}

#[derive(Debug, Clone, PackAbiPlain, KnownParamTypePlain, UnpackAbiPlain)]
pub struct ChangeOwnerInputs {
    #[abi(address, name = "newOwner")]
    pub new_owner: MsgAddressInt,
    #[abi(address, name = "sendGasTo")]
    pub send_gas_to: MsgAddressInt,
    pub callbacks: BTreeMap<MsgAddressInt, NftCallbackPayload>,
}

#[derive(Debug, Clone, PackAbiPlain, KnownParamTypePlain, UnpackAbiPlain)]
pub struct ChangeManagerInputs {
    #[abi(address, name = "newManager")]
    pub new_manager: MsgAddressInt,
    #[abi(address, name = "sendGasTo")]
    pub send_gas_to: MsgAddressInt,
    pub callbacks: BTreeMap<MsgAddressInt, NftCallbackPayload>,
}

#[derive(Debug, Clone, PackAbiPlain, KnownParamTypePlain, UnpackAbiPlain)]
pub struct TransferInputs {
    #[abi(address, name = "to")]
    pub to: MsgAddressInt,
    #[abi(address, name = "sendGasTo")]
    pub send_gas_to: MsgAddressInt,
    pub callbacks: BTreeMap<MsgAddressInt, NftCallbackPayload>,
}

///Change NFT owner
///
/// # Type
/// Internal method
///
/// # Dev
/// Invoked from manager address only
///
/// # Inputs
/// * `newOwner: address` - New owner of NFT
/// * `sendGasTo: address` - Address to send remaining gas
/// * `callbacks: map(address, tuple)` - Callbacks array to send by addresses. It can be empty
///
pub fn change_owner() -> &'static ton_abi::Function {
    declare_function! {
        name: "changeOwner",
        inputs: ChangeOwnerInputs::param_type(),
        outputs: vec![],
    }
}

///Change NFT manager
///
/// # Type
/// Internal method
///
/// # Dev
/// Invoked from manager address only
///
/// # Inputs
/// * `newOwner: address` - New manager of NFT
/// * `sendGasTo: address` - Address to send remaining gas
/// * `callbacks: map(address, tuple)` - Callbacks array to send by addresses. It can be empty
///
pub fn change_manager() -> &'static ton_abi::Function {
    declare_function! {
        name: "changeManager",
        inputs: ChangeManagerInputs::param_type(),
        outputs: vec![],
    }
}

///Change NFT owner and manager
///
/// # Type
/// Internal method
///
/// # Dev
/// Invoked from manager address only
///
/// # Inputs
/// * `newOwner: address` - New manager of NFT
/// * `sendGasTo: address` - Address to send remaining gas
/// * `callbacks: map(address, tuple)` - Callbacks array to send by addresses. It can be empty
///
pub fn transfer() -> &'static ton_abi::Function {
    declare_function! {
        name: "transfer",
        inputs: TransferInputs::param_type(),
        outputs: vec![],
    }
}

#[derive(Debug, Clone, PackAbi, KnownParamType, UnpackAbi)]
pub struct NftCallbackPayload {
    #[abi(uint128)]
    pub value: u128,
    #[abi(cell)]
    pub payload: Cell,
}
