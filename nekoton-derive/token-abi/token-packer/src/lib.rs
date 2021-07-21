pub use num_bigint;

use num_bigint::{BigInt, BigUint};
use ton_abi::{Token, TokenValue};
use ton_block::{MsgAddrStd, MsgAddress, MsgAddressInt};
use ton_types::{Cell, UInt256};

pub trait PackTokens {
    fn pack(self) -> Vec<Token>;
}

pub trait BuildTokenValue {
    fn token_value(self) -> TokenValue;
}

pub trait BuildTokenValues {
    fn token_values(self) -> Vec<TokenValue>;
}

impl BuildTokenValue for bool {
    fn token_value(self) -> TokenValue {
        TokenValue::Bool(self)
    }
}

impl BuildTokenValue for &str {
    fn token_value(self) -> TokenValue {
        TokenValue::Bytes(self.as_bytes().into())
    }
}

impl BuildTokenValue for i8 {
    fn token_value(self) -> TokenValue {
        TokenValue::Int(ton_abi::Int {
            number: BigInt::from(self),
            size: 8,
        })
    }
}

impl BuildTokenValue for u8 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from(self),
            size: 8,
        })
    }
}

impl BuildTokenValue for u16 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from(self),
            size: 16,
        })
    }
}

impl BuildTokenValue for u32 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from(self),
            size: 32,
        })
    }
}

impl BuildTokenValue for u64 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from(self),
            size: 64,
        })
    }
}

impl BuildTokenValue for u128 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from(self),
            size: 64,
        })
    }
}

impl BuildTokenValue for Vec<u8> {
    fn token_value(self) -> TokenValue {
        TokenValue::Bytes(self)
    }
}

impl BuildTokenValue for MsgAddrStd {
    fn token_value(self) -> TokenValue {
        TokenValue::Address(MsgAddress::AddrStd(self))
    }
}

impl BuildTokenValue for MsgAddressInt {
    fn token_value(self) -> TokenValue {
        TokenValue::Address(match self {
            MsgAddressInt::AddrStd(addr) => MsgAddress::AddrStd(addr),
            MsgAddressInt::AddrVar(addr) => MsgAddress::AddrVar(addr),
        })
    }
}

impl BuildTokenValue for Cell {
    fn token_value(self) -> TokenValue {
        TokenValue::Cell(self)
    }
}

impl BuildTokenValue for UInt256 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from_bytes_be(self.as_slice()),
            size: 256,
        })
    }
}

impl<T> BuildTokenValue for Vec<T>
where
    T: StandaloneToken + BuildTokenValue,
{
    fn token_value(self) -> TokenValue {
        TokenValue::Array(self.into_iter().map(BuildTokenValue::token_value).collect())
    }
}

impl BuildTokenValue for TokenValue {
    fn token_value(self) -> TokenValue {
        self
    }
}

impl<T> BuildTokenValue for &T
where
    T: Clone + BuildTokenValue,
{
    fn token_value(self) -> TokenValue {
        self.clone().token_value()
    }
}

impl<T> BuildTokenValues for &T
where
    T: Clone + BuildTokenValues,
{
    fn token_values(self) -> Vec<TokenValue> {
        self.clone().token_values()
    }
}

pub trait StandaloneToken {}
impl StandaloneToken for MsgAddressInt {}
impl StandaloneToken for MsgAddrStd {}
impl StandaloneToken for UInt256 {}
impl StandaloneToken for u16 {}
impl StandaloneToken for u32 {}
impl StandaloneToken for u64 {}
impl StandaloneToken for u128 {}
impl StandaloneToken for bool {}
impl StandaloneToken for Vec<u8> {}
impl StandaloneToken for TokenValue {}
