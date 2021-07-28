use num_traits::ToPrimitive;
use ton_abi::TokenValue;
use ton_abi::{Token, Uint};

use nekoton_parser::abi::{UnpackAbi, UnpackToken, UnpackerError, UnpackerResult};

#[derive(UnpackAbi)]
struct Data {
    #[abi(unpack_with = "external_unpacker")]
    value: u32,
}

fn external_unpacker(value: &TokenValue) -> UnpackerResult<u32> {
    match value {
        ton_abi::TokenValue::Uint(ton_abi::Uint {
            number: value,
            size: 20,
        }) => value.to_u32().ok_or(UnpackerError::InvalidAbi),
        _ => Err(UnpackerError::InvalidAbi),
    }
}

fn test() -> Data {
    let value = Token::new("value", TokenValue::Uint(Uint::new(10, 20)));
    let tokens = vec![value];

    let tuple = Token::new("tuple", TokenValue::Tuple(tokens));
    let parsed: Data = tuple.unpack().unwrap();

    parsed
}

fn main() {
    let data = test();
    assert_eq!(data.value, 10);
}
