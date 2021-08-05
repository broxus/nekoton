use num_bigint::BigUint;
use ton_abi::TokenValue;

use nekoton_abi::{PackAbiPlain, UnpackAbiPlain};

#[derive(PackAbiPlain, UnpackAbiPlain)]
struct Data {
    #[abi(name = "value", pack_with = "external_packer")]
    value: u32,
}

fn external_packer(value: u32) -> TokenValue {
    TokenValue::Uint(ton_abi::Uint {
        number: BigUint::from(value),
        size: 32,
    })
}

fn main() {
    let data = Data { value: 10 };
    let tokens: Vec<ton_abi::Token> = data.pack();
    let new_data: Data = tokens.unpack().unwrap();
    assert_eq!(new_data.value, 10);
}
