use std::str::FromStr;

use num_bigint::BigUint;
use num_traits::FromPrimitive;
use ton_abi::TokenValue;
use ton_abi::{Token, Uint};
use ton_block::{MsgAddress, MsgAddressInt};
use ton_types::UInt256;

use nekoton_abi::{uint256_bytes, UnpackAbiPlain};

#[derive(UnpackAbiPlain, Debug)]
pub struct InternalTransfer {
    #[abi]
    pub tokens: u128,
    #[abi(with = "uint256_bytes")]
    pub sender_public_key: UInt256,
    #[abi(address)]
    pub sender_address: MsgAddressInt,
}

fn test() -> InternalTransfer {
    let tokens = TokenValue::Uint(Uint {
        number: BigUint::from_u64(1337).unwrap(),
        size: 128,
    });
    let tokens = Token::new("tokens", tokens);
    let sender_public_key = TokenValue::Uint(Uint {
        number: BigUint::from_u64(13373424234).unwrap(),
        size: 256,
    });
    let sender_public_key = Token::new("sender_public_key", sender_public_key);
    let address = match MsgAddressInt::from_str(
        "0:18c99afffe13d3081370f77c10fc4d51bc54e52b8e181db6a0e8bb75456d91ff",
    )
    .unwrap()
    {
        MsgAddressInt::AddrStd(a) => a,
        MsgAddressInt::AddrVar(_) => unreachable!(),
    };
    let sender_address = TokenValue::Address(MsgAddress::AddrStd(address));
    let sender_address = Token::new("sender_address", sender_address);
    let tokens = vec![tokens, sender_public_key, sender_address];
    let parsed: InternalTransfer = tokens.unpack().unwrap();
    parsed
}

fn main() {
    let data = test();
    assert_eq!(data.tokens, 1337);
    assert_eq!(
        data.sender_public_key.to_hex_string(),
        "000000000000000000000000000000000000000000000000000000031d1e426a"
    );
    assert_eq!(
        data.sender_address.to_string(),
        "0:18c99afffe13d3081370f77c10fc4d51bc54e52b8e181db6a0e8bb75456d91ff"
    );
}
