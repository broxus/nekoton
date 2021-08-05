use num_bigint::BigUint;
use ton_abi::{TokenValue, Uint};
use ton_types::UInt256;

use nekoton_utils::UInt128;

use super::{BuildTokenValue, UnpackerError, UnpackerResult};

pub struct BigUint128(pub BigUint);

impl BuildTokenValue for BigUint128 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(Uint {
            number: self.0,
            size: 128,
        })
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

impl BuildTokenValue for UInt256 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(Uint {
            number: BigUint::from_bytes_be(self.as_slice()),
            size: 256,
        })
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
}

pub mod uint128_bytes {
    use super::*;

    pub fn pack(value: UInt128) -> TokenValue {
        BigUint128(BigUint::from_bytes_be(value.as_slice())).token_value()
    }

    pub fn unpack(value: &TokenValue) -> UnpackerResult<UInt128> {
        match value {
            TokenValue::Uint(Uint { number, size: 128 }) => Ok(number.to_bytes_be().into()),
            _ => Err(UnpackerError::InvalidAbi),
        }
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
}
