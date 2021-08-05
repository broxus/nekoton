use num_bigint::BigUint;
use ton_abi::{Int, Token, TokenValue, Uint};
use ton_types::UInt256;

use nekoton_abi::*;

#[derive(UnpackAbiPlain)]
struct Data {
    #[abi(int8)]
    data_i8: i8,
    #[abi(uint8)]
    data_u8: u8,
    #[abi(uint16)]
    data_u16: u16,
    #[abi(uint32)]
    data_u32: u32,
    #[abi(uint64)]
    data_u64: u64,
    #[abi(uint128)]
    data_u128: u128,
    #[abi(with = "uint160_bytes")]
    data_u160: [u8; 20],
    #[abi(with = "uint256_bytes")]
    data_u256: UInt256,
    #[abi(with = "uint128_number")]
    data_uint128_number: BigUint,
    #[abi(bool)]
    data_bool: bool,
    #[abi(bytes)]
    data_bytes: Vec<u8>,
}

fn test() -> Data {
    let data_i8 = Token::new("data_i8", TokenValue::Int(Int::new(8, 8)));
    let data_u8 = Token::new("data_u8", TokenValue::Uint(Uint::new(8, 8)));
    let data_u16 = Token::new("data_u16", TokenValue::Uint(Uint::new(16, 16)));
    let data_u32 = Token::new("data_u32", TokenValue::Uint(Uint::new(32, 32)));
    let data_u64 = Token::new("data_u64", TokenValue::Uint(Uint::new(64, 64)));
    let data_u128 = Token::new("data_u128", TokenValue::Uint(Uint::new(128, 128)));
    let data_u160 = Token::new("data_u160", TokenValue::Uint(Uint::new(160, 160)));
    let data_u256 = Token::new("data_u256", TokenValue::Uint(Uint::new(256, 256)));
    let data_uint128_number =
        Token::new("data_uint128_number", TokenValue::Uint(Uint::new(128, 128)));
    let data_bool = Token::new("data_bool", TokenValue::Bool(true));
    let data_bytes = Token::new("data_bytes", TokenValue::Bytes(Vec::from("Test")));

    let tokens = vec![
        data_i8,
        data_u8,
        data_u16,
        data_u32,
        data_u64,
        data_u128,
        data_u160,
        data_u256,
        data_uint128_number,
        data_bool,
        data_bytes,
    ];
    let parsed: Data = tokens.unpack().unwrap();

    parsed
}

fn main() {
    let data = test();

    assert_eq!(data.data_i8, 8);
    assert_eq!(data.data_u8, 8);
    assert_eq!(data.data_u16, 16);
    assert_eq!(data.data_u32, 32);
    assert_eq!(data.data_u64, 64);
    assert_eq!(data.data_u128, 128);
    assert_eq!(
        data.data_u256.to_hex_string(),
        "0000000000000000000000000000000000000000000000000000000000000100"
    );
    assert_eq!(data.data_bool, true);

    {
        let bytes = data.data_uint128_number.to_bytes_be();
        assert!(bytes.len() <= 16);

        let mut padded_data = [0u8; 16];
        let offset = padded_data.len() - bytes.len();
        padded_data[offset..16].copy_from_slice(&bytes);

        assert_eq!(hex::encode(padded_data), "00000000000000000000000000000080");
    }

    assert_eq!(
        hex::encode(data.data_u160),
        "00000000000000000000000000000000000000a0"
    );

    assert_eq!(data.data_bytes, Vec::from("Test"));
}
