use std::str::FromStr;

use num_bigint::BigUint;
use num_traits::FromPrimitive;
use ton_abi::{ParamType, TokenValue};
use ton_abi::{Token, Uint};
use ton_block::{MsgAddress, MsgAddressInt};
use ton_types::UInt256;

use nekoton_abi::{uint256_bytes, BuildTokenValue, Maybe, MaybeRef, UnpackAbiPlain};

#[derive(UnpackAbiPlain, Debug)]
pub struct InternalTransfer {
    #[abi]
    pub tokens: u128,
    #[abi(with = "uint256_bytes")]
    pub sender_public_key: UInt256,
    #[abi(address)]
    pub sender_address: MsgAddressInt,
    #[abi]
    pub maybe_int: Maybe<u32>,
    #[abi]
    pub maybe_ref_int: MaybeRef<u32>,
    #[abi(string)]
    pub test: String,
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
    let maybe_int = Token::new(
        "maybe_int",
        TokenValue::Optional(ParamType::Uint(32), Some(Box::new(123u32.token_value()))),
    );
    let maybe_ref_int = Token::new(
        "maybe_ref_int",
        TokenValue::Optional(
            ParamType::Ref(Box::new(ParamType::Uint(32))),
            Some(Box::new(TokenValue::Ref(Box::new(321u32.token_value())))),
        ),
    );
    let test = Token::new("test", TokenValue::String("Asd".to_string()));
    let tokens = vec![
        tokens,
        sender_public_key,
        sender_address,
        maybe_int,
        maybe_ref_int,
        test,
    ];
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
    assert_eq!(data.maybe_int.0, Some(123u32));
    assert_eq!(data.maybe_ref_int.0, Some(321u32));
}
