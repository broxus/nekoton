use num_bigint::BigUint;
use ton_abi::{Token, TokenValue};

use nekoton_utils::UInt128;

use super::{BuildTokenValue, UnpackerError, UnpackerResult};

pub struct BigUint128(pub BigUint);

impl BuildTokenValue for BigUint128 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: self.0,
            size: 128,
        })
    }
}

pub fn pack(name: &str, value: UInt128) -> Token {
    Token::new(
        name,
        BigUint128(BigUint::from_bytes_be(value.as_slice())).token_value(),
    )
}

pub fn unpack(value: &TokenValue) -> UnpackerResult<UInt128> {
    match value {
        TokenValue::Uint(data) => Ok(data.number.to_bytes_be().into()),
        _ => Err(UnpackerError::InvalidAbi),
    }
}
