use num_bigint::BigUint;
use ton_abi::{Token, TokenValue, Uint};
use ton_types::UInt256;

use super::{BuildTokenValue, ContractResult, UnpackerError};

pub struct BigUint256(pub BigUint);

impl BuildTokenValue for BigUint256 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: self.0,
            size: 256,
        })
    }
}

impl BuildTokenValue for UInt256 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(Uint {
            number: num_bigint::BigUint::from_bytes_be(self.as_slice()),
            size: 256,
        })
    }
}

pub fn pack(name: &str, value: UInt256) -> Token {
    Token::new(
        name,
        BigUint256(BigUint::from_bytes_be(value.as_slice())).token_value(),
    )
}

pub fn unpack(value: &TokenValue) -> ContractResult<UInt256> {
    match value {
        TokenValue::Uint(data) => {
            let mut result = [0u8; 32];
            let data = data.number.to_bytes_be();

            let len = std::cmp::min(data.len(), 32);
            let offset = 32 - len;
            (0..len).for_each(|i| result[i + offset] = data[i]);

            Ok(result.into())
        }
        _ => Err(UnpackerError::InvalidAbi),
    }
}
