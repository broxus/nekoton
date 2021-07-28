use num_bigint::BigUint;
use ton_abi::{Token, TokenValue, Uint};

use super::{UnpackerError, UnpackerResult};

pub fn pack(name: &str, value: BigUint) -> Token {
    Token::new(
        name,
        TokenValue::Uint(Uint {
            number: value,
            size: 128,
        }),
    )
}

pub fn unpack(value: &TokenValue) -> UnpackerResult<BigUint> {
    match value {
        TokenValue::Uint(ton_abi::Uint {
            number: data,
            size: 128,
        }) => Ok(data.clone()),
        _ => Err(UnpackerError::InvalidAbi),
    }
}
