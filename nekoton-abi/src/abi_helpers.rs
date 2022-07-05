use std::collections::BTreeMap;
use std::str::FromStr;

use num_bigint::BigUint;
use ton_abi::{ParamType, TokenValue, Uint};
use ton_types::UInt256;

use super::{BuildTokenValue, KnownParamType, UnpackAbi, UnpackerError, UnpackerResult};

pub struct BigUint128(pub BigUint);

impl BuildTokenValue for BigUint128 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(Uint {
            number: self.0,
            size: 128,
        })
    }
}

impl KnownParamType for BigUint128 {
    fn param_type() -> ParamType {
        ParamType::Uint(128)
    }
}

pub struct BigUint256(pub BigUint);

impl BuildTokenValue for BigUint256 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(Uint {
            number: self.0,
            size: 256,
        })
    }
}

impl KnownParamType for BigUint256 {
    fn param_type() -> ParamType {
        ParamType::Uint(256)
    }
}

impl BuildTokenValue for UInt256 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(Uint {
            number: BigUint::from_bytes_be(self.as_slice()),
            size: 256,
        })
    }
}

impl KnownParamType for UInt256 {
    fn param_type() -> ParamType {
        ParamType::Uint(256)
    }
}

pub mod uint256_bytes {
    use super::*;

    pub fn pack(value: UInt256) -> TokenValue {
        BigUint256(BigUint::from_bytes_be(value.as_slice())).token_value()
    }

    pub fn unpack(value: &TokenValue) -> UnpackerResult<UInt256> {
        match value {
            TokenValue::Uint(Uint { number, size: 256 }) => {
                let mut result = [0u8; 32];
                let data = number.to_bytes_be();

                let len = std::cmp::min(data.len(), 32);
                let offset = 32 - len;
                (0..len).for_each(|i| result[i + offset] = data[i]);

                Ok(result.into())
            }
            _ => Err(UnpackerError::InvalidAbi),
        }
    }

    pub fn param_type() -> ParamType {
        ParamType::Uint(256)
    }
}

pub mod bytes_as_string {
    use super::*;

    pub fn pack(value: String) -> TokenValue {
        TokenValue::Bytes(value.into_bytes())
    }

    pub fn unpack(value: &TokenValue) -> UnpackerResult<String> {
        match value {
            TokenValue::Bytes(data) => Ok(String::from_utf8_lossy(data).to_string()),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }

    pub fn param_type() -> ParamType {
        ParamType::Bytes
    }
}

pub mod uint256_number {
    use super::*;

    pub fn pack(value: BigUint) -> TokenValue {
        BigUint256(value).token_value()
    }

    pub fn unpack(value: &TokenValue) -> UnpackerResult<BigUint> {
        match value {
            TokenValue::Uint(Uint { number, size: 256 }) => Ok(number.clone()),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }

    pub fn param_type() -> ParamType {
        ParamType::Uint(256)
    }
}

pub mod array_uint256_bytes {
    use super::*;

    pub fn pack(value: Vec<UInt256>) -> TokenValue {
        TokenValue::Array(
            ton_abi::ParamType::Uint(256),
            value.into_iter().map(uint256_bytes::pack).collect(),
        )
    }

    pub fn unpack(value: &TokenValue) -> UnpackerResult<Vec<UInt256>> {
        match value {
            TokenValue::Array(ton_abi::ParamType::Uint(256), array) => {
                array.iter().map(uint256_bytes::unpack).collect()
            }
            _ => Err(UnpackerError::InvalidAbi),
        }
    }

    pub fn param_type() -> ParamType {
        ParamType::Array(Box::new(ParamType::Uint(256)))
    }
}

pub mod uint160_bytes {
    use super::*;

    pub fn pack(value: [u8; 20]) -> TokenValue {
        TokenValue::Uint(Uint {
            number: BigUint::from_bytes_be(&value),
            size: 160,
        })
    }

    pub fn unpack(value: &TokenValue) -> UnpackerResult<[u8; 20]> {
        match value {
            TokenValue::Uint(Uint { number, size: 160 }) => {
                let mut result = [0u8; 20];
                let data = number.to_bytes_be();
                if data.len() > 20 {
                    return Err(UnpackerError::InvalidAbi);
                }

                let offset = result.len() - data.len();
                result[offset..20].copy_from_slice(&data);

                Ok(result)
            }
            _ => Err(UnpackerError::InvalidAbi),
        }
    }

    pub fn param_type() -> ParamType {
        ParamType::Uint(160)
    }
}

pub mod array_uint160_bytes {
    use super::*;

    pub fn pack(value: Vec<[u8; 20]>) -> TokenValue {
        TokenValue::Array(
            ton_abi::ParamType::Uint(160),
            value.into_iter().map(uint160_bytes::pack).collect(),
        )
    }

    pub fn unpack(value: &TokenValue) -> UnpackerResult<Vec<[u8; 20]>> {
        match value {
            TokenValue::Array(ton_abi::ParamType::Uint(160), array) => {
                array.iter().map(uint160_bytes::unpack).collect()
            }
            _ => Err(UnpackerError::InvalidAbi),
        }
    }

    pub fn param_type() -> ParamType {
        ParamType::Array(Box::new(ParamType::Uint(160)))
    }
}

pub mod uint128_number {
    use super::*;

    pub fn pack(value: BigUint) -> TokenValue {
        TokenValue::Uint(Uint {
            number: value,
            size: 128,
        })
    }

    pub fn unpack(value: &TokenValue) -> UnpackerResult<BigUint> {
        match value {
            TokenValue::Uint(ton_abi::Uint { number, size: 128 }) => Ok(number.clone()),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }

    pub fn param_type() -> ParamType {
        ParamType::Uint(128)
    }
}

pub mod address_only_hash {
    use super::*;

    pub fn pack(value: UInt256) -> TokenValue {
        TokenValue::Address(ton_block::MsgAddress::AddrStd(ton_block::MsgAddrStd {
            anycast: None,
            workchain_id: 0,
            address: value.into(),
        }))
    }

    pub fn unpack(value: &TokenValue) -> UnpackerResult<UInt256> {
        match value {
            TokenValue::Address(ton_block::MsgAddress::AddrStd(ton_block::MsgAddrStd {
                address,
                ..
            })) => Ok(UInt256::from_be_bytes(&address.get_bytestring(0))),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }

    pub fn param_type() -> ParamType {
        ParamType::Address
    }
}

pub mod array_address_only_hash {
    use super::*;

    pub fn pack(value: Vec<UInt256>) -> TokenValue {
        ton_abi::TokenValue::Array(
            param_type(),
            value
                .into_iter()
                .map(|value| {
                    TokenValue::Address(ton_block::MsgAddress::AddrStd(ton_block::MsgAddrStd {
                        anycast: None,
                        workchain_id: 0,
                        address: value.into(),
                    }))
                })
                .collect(),
        )
    }

    pub fn unpack(value: &TokenValue) -> UnpackerResult<Vec<UInt256>> {
        match value {
            TokenValue::Array(_, values) => {
                let mut result = Vec::with_capacity(values.len());
                for value in values {
                    match value {
                        TokenValue::Address(ton_block::MsgAddress::AddrStd(
                            ton_block::MsgAddrStd { address, .. },
                        )) => result.push(UInt256::from_be_bytes(&address.get_bytestring(0))),
                        _ => return Err(UnpackerError::InvalidAbi),
                    }
                }
                Ok(result)
            }
            _ => Err(UnpackerError::InvalidAbi),
        }
    }

    pub fn param_type() -> ParamType {
        ton_abi::ParamType::Array(Box::new(ParamType::Address))
    }
}

pub mod map_integer_tuple {
    use super::*;

    pub fn unpack<K, V>(value: &TokenValue) -> UnpackerResult<BTreeMap<K, V>>
    where
        K: Ord + FromStr,
        TokenValue: UnpackAbi<V>,
    {
        match value {
            TokenValue::Map(ParamType::Uint(64), _, values) => {
                let mut map = BTreeMap::<K, V>::new();
                for (key, value) in values {
                    let key = key.parse::<K>().map_err(|_| UnpackerError::InvalidAbi)?;
                    let value: V = value.to_owned().unpack()?;
                    map.insert(key, value);
                }
                Ok(map)
            }
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}
