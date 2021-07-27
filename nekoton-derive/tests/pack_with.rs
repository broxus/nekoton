use num_bigint::BigUint;
use ton_abi::Token;
use ton_abi::TokenValue;

use nekoton_parser::abi::{PackAbi, PackTokens, UnpackAbi, UnpackToken};

#[derive(PackAbi, UnpackAbi)]
#[abi(plain)]
struct Data {
    #[abi(name = "value", pack_with = "external_packer")]
    value: u32,
}

fn external_packer(name: &str, value: u32) -> Token {
    Token::new(
        name,
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from(value),
            size: 32,
        }),
    )
}

fn main() {
    let data = Data { value: 10 };
    let tokens = data.pack();
    let new_data: Data = tokens.unpack().unwrap();
    assert_eq!(new_data.value, 10);
}
