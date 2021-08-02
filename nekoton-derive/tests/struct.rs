use std::str::FromStr;

use num_bigint::BigUint;
use num_traits::FromPrimitive;
use ton_abi::TokenValue;
use ton_abi::{Token, Uint};
use ton_block::{MsgAddress, MsgAddressInt};
use ton_types::UInt256;

use nekoton_abi::{uint256_bytes, PackAbi, UnpackAbi};

#[derive(PackAbi, UnpackAbi, Clone)]
struct PendingTransaction {
    #[abi(uint64)]
    id: u64,
    #[abi(uint32, name = "confirmationsMask")]
    confirmations_mask: u32,
    #[abi(uint8, name = "signsRequired")]
    signs_required: u8,
    #[abi(uint8, name = "signsReceived")]
    signs_received: u8,
    #[abi(name = "creator", with = "uint256_bytes")]
    creator: UInt256,
    #[abi(uint8)]
    index: u8,
    #[abi(address)]
    dest: MsgAddressInt,
    //value: BigUint,
    #[abi(uint16, name = "sendFlags")]
    send_flags: u16,
    //payload: ton_types::Cell,
    #[abi(bool)]
    bounce: bool,
    #[abi]
    complex: Complex,
}

#[derive(PackAbi, UnpackAbi, Clone)]
struct Complex {
    #[abi]
    number: u8,
    #[abi]
    flag: bool,
    #[abi(name = "publicKey")]
    public_key: Vec<u8>,
}

fn test_unpacker() -> PendingTransaction {
    let number = Token::new("number", TokenValue::Uint(Uint::new(33, 8)));
    let flag = Token::new("flag", TokenValue::Bool(true));
    let public_key = Token::new(
        "publicKey",
        TokenValue::Bytes(
            hex::decode("6775b6a6ba3711a1c9ac1a62cacf62890ad1df5fbe4308dd9a17405c75b57f2e")
                .unwrap(),
        ),
    );
    let complex = vec![number, flag, public_key];

    let id = Token::new("id", TokenValue::Uint(Uint::new(10, 64)));
    let confirmations_mask = Token::new("confirmationsMask", TokenValue::Uint(Uint::new(5, 32)));
    let signs_required = Token::new("signsRequired", TokenValue::Uint(Uint::new(7, 8)));
    let signs_received = Token::new("signsReceived", TokenValue::Uint(Uint::new(3, 8)));
    let creator = Token::new(
        "creator",
        TokenValue::Uint(Uint {
            number: BigUint::from_u64(12345).unwrap(),
            size: 256,
        }),
    );
    let index = Token::new("index", TokenValue::Uint(Uint::new(9, 8)));
    let dest = Token::new(
        "dest",
        TokenValue::Address(MsgAddress::AddrStd(
            match MsgAddressInt::from_str(
                "0:18c99afffe13d3081370f77c10fc4d51bc54e52b8e181db6a0e8bb75456d91ff",
            )
            .unwrap()
            {
                MsgAddressInt::AddrStd(a) => a,
                MsgAddressInt::AddrVar(_) => unreachable!(),
            },
        )),
    );
    let send_flags = Token::new("sendFlags", TokenValue::Uint(Uint::new(12, 16)));
    let bounce = Token::new("bounce", TokenValue::Bool(false));
    let complex = Token::new("complex", TokenValue::Tuple(complex));

    let tokens = vec![
        id,
        confirmations_mask,
        signs_required,
        signs_received,
        creator,
        index,
        dest,
        send_flags,
        bounce,
        complex,
    ];

    let tuple = Token::new("tuple", TokenValue::Tuple(tokens));
    let parsed: PendingTransaction = tuple.unpack().unwrap();

    parsed
}

fn test_packer(data: PendingTransaction) -> PendingTransaction {
    let token = data.pack();
    let parsed: PendingTransaction = token.unpack().unwrap();

    parsed
}

fn main() {
    let data = test_unpacker();
    assert_eq!(data.id, 10);
    assert_eq!(data.confirmations_mask, 5);
    assert_eq!(data.signs_required, 7);
    assert_eq!(data.signs_received, 3);
    assert_eq!(
        data.creator.to_hex_string(),
        "0000000000000000000000000000000000000000000000000000000000003039"
    );
    assert_eq!(data.index, 9);
    assert_eq!(
        data.dest.to_string(),
        "0:18c99afffe13d3081370f77c10fc4d51bc54e52b8e181db6a0e8bb75456d91ff"
    );
    assert_eq!(data.send_flags, 12);
    assert_eq!(data.bounce, false);
    assert_eq!(data.complex.number, 33);
    assert_eq!(
        data.complex.public_key,
        hex::decode("6775b6a6ba3711a1c9ac1a62cacf62890ad1df5fbe4308dd9a17405c75b57f2e").unwrap()
    );
    assert_eq!(data.complex.flag, true);

    let new_data = test_packer(data.clone());
    assert_eq!(data.id, new_data.id);
    assert_eq!(data.confirmations_mask, new_data.confirmations_mask);
    assert_eq!(data.signs_required, new_data.signs_required);
    assert_eq!(data.signs_received, new_data.signs_received);
    assert_eq!(data.creator, new_data.creator);
    assert_eq!(data.index, new_data.index);
    assert_eq!(data.dest, new_data.dest);
    assert_eq!(data.send_flags, new_data.send_flags);
    assert_eq!(data.bounce, new_data.bounce);
    assert_eq!(data.complex.number, new_data.complex.number);
    assert_eq!(data.complex.flag, new_data.complex.flag);
    assert_eq!(data.complex.public_key, new_data.complex.public_key);
}
