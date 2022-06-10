use nekoton_abi::num_traits::ToPrimitive;
use nekoton_abi::*;
use std::collections::BTreeMap;
use ton_abi::{Param, ParamType, TokenValue};
use ton_block::MsgAddressInt;
use ton_types::{Cell, UInt256};

use crate::utils::declare_function;

pub const INTERFACE_ID: u32 = 0x78084F7E;

#[derive(Debug, Clone, KnownParamTypePlain, PackAbiPlain, UnpackAbiPlain)]
pub struct GetInfoOutputs {
    #[abi(with = "uint256_bytes")]
    pub id: UInt256,
    #[abi(address)]
    pub owner: ton_block::MsgAddressInt,
    #[abi(address)]
    pub manager: ton_block::MsgAddressInt,
    #[abi(address)]
    pub collection: ton_block::MsgAddressInt,
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
    #[abi(with = "map_address_tuple")]
    pub callbacks: BTreeMap<String, NftCallbackPayload>,
}

#[derive(Debug, Clone, PackAbiPlain, KnownParamTypePlain, UnpackAbiPlain)]
pub struct ChangeManagerInputs {
    #[abi(address, name = "newManager")]
    pub new_manager: MsgAddressInt,
    #[abi(address, name = "sendGasTo")]
    pub send_gas_to: MsgAddressInt,
    #[abi(with = "map_address_tuple")]
    pub callbacks: BTreeMap<String, NftCallbackPayload>,
}

#[derive(Debug, Clone, PackAbiPlain, KnownParamTypePlain, UnpackAbiPlain)]
pub struct TransferInputs {
    #[abi(address, name = "to")]
    pub to: MsgAddressInt,
    #[abi(address, name = "sendGasTo")]
    pub send_gas_to: MsgAddressInt,
    #[abi(with = "map_address_tuple")]
    pub callbacks: BTreeMap<String, NftCallbackPayload>,
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

#[derive(Debug, Clone)]
pub struct NftCallbackPayload {
    pub value: u128,
    pub payload: Cell,
}

impl UnpackAbiPlain<NftCallbackPayload> for Vec<::ton_abi::Token> {
    fn unpack(self) -> UnpackerResult<NftCallbackPayload> {
        let mut tokens = self.into_iter();
        let value = match tokens.next().unwrap().value {
            TokenValue::Uint(ton_abi::Uint { number, size: 128 }) => number.to_u128().unwrap(),
            _ => return Err(UnpackerError::InvalidAbi),
        };
        let payload = match tokens.next().unwrap().value {
            TokenValue::Cell(cell) => cell,
            _ => return Err(UnpackerError::InvalidAbi),
        };
        Ok(NftCallbackPayload { value, payload })
    }
}

pub mod map_address_tuple {
    use super::*;
    use ton_abi::{Param, Token};
    use UnpackAbiPlain;

    pub fn unpack(value: &TokenValue) -> UnpackerResult<BTreeMap<String, NftCallbackPayload>> {
        match value {
            TokenValue::Map(ParamType::Address, _, values) => {
                let mut map = BTreeMap::<String, NftCallbackPayload>::new();
                for (key, value) in values {
                    let key = key.clone();

                    let value: NftCallbackPayload = match value {
                        TokenValue::Tuple(vec) => vec.clone().unpack()?,
                        _ => return Err(UnpackerError::InvalidAbi),
                    };
                    map.insert(key, value);
                }
                Ok(map)
            }
            _ => Err(UnpackerError::InvalidAbi),
        }
    }

    pub fn pack(value: BTreeMap<String, NftCallbackPayload>) -> TokenValue {
        ton_abi::TokenValue::Map(
            param_type_key(),
            param_type_value(),
            value
                .into_iter()
                .map(|value| {
                    (
                        value.0.to_string(),
                        TokenValue::Tuple(vec![
                            Token::new(
                                "value",
                                TokenValue::Uint(ton_abi::Uint::new(value.1.value, 128usize)),
                            ),
                            Token::new("payload", TokenValue::Cell(value.1.payload)),
                        ]),
                    )
                })
                .collect(),
        )
    }

    pub fn param_type() -> ParamType {
        ParamType::Map(Box::new(param_type_key()), Box::new(param_type_value()))
    }

    pub fn param_type_key() -> ParamType {
        ParamType::Address
    }

    pub fn param_type_value() -> ParamType {
        ParamType::Tuple(vec![
            Param::new("value", ParamType::Uint(128)),
            Param::new("payload", ParamType::Cell),
        ])
    }
}
