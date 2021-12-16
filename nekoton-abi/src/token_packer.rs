use num_bigint::{BigInt, BigUint};
use ton_abi::{Token, TokenValue};
use ton_block::{MsgAddrStd, MsgAddress, MsgAddressInt};
use ton_types::{BuilderData, Cell};

use super::{KnownParamType, Maybe, MaybeRef, StandaloneToken};

pub trait PackAbiPlain {
    fn pack(self) -> Vec<Token>;
}

pub trait PackAbi: BuildTokenValue {
    fn pack(self) -> TokenValue;
}

pub trait BuildTokenValue {
    fn token_value(self) -> TokenValue;
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

impl BuildTokenValue for i16 {
    fn token_value(self) -> TokenValue {
        TokenValue::Int(ton_abi::Int {
            number: BigInt::from(self),
            size: 16,
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

impl BuildTokenValue for i32 {
    fn token_value(self) -> TokenValue {
        TokenValue::Int(ton_abi::Int {
            number: BigInt::from(self),
            size: 32,
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

impl BuildTokenValue for i64 {
    fn token_value(self) -> TokenValue {
        TokenValue::Int(ton_abi::Int {
            number: BigInt::from(self),
            size: 64,
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

impl BuildTokenValue for i128 {
    fn token_value(self) -> TokenValue {
        TokenValue::Int(ton_abi::Int {
            number: BigInt::from(self),
            size: 128,
        })
    }
}

impl BuildTokenValue for u128 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from(self),
            size: 128,
        })
    }
}

impl BuildTokenValue for bool {
    fn token_value(self) -> TokenValue {
        TokenValue::Bool(self)
    }
}

impl BuildTokenValue for Cell {
    fn token_value(self) -> TokenValue {
        TokenValue::Cell(self)
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

impl BuildTokenValue for MsgAddrStd {
    fn token_value(self) -> TokenValue {
        TokenValue::Address(MsgAddress::AddrStd(self))
    }
}

impl BuildTokenValue for &str {
    fn token_value(self) -> TokenValue {
        TokenValue::String(self.to_string())
    }
}

impl BuildTokenValue for String {
    fn token_value(self) -> TokenValue {
        TokenValue::String(self)
    }
}

impl BuildTokenValue for ton_block::Grams {
    fn token_value(self) -> TokenValue {
        TokenValue::Token(self)
    }
}

impl BuildTokenValue for Vec<u8> {
    fn token_value(self) -> TokenValue {
        TokenValue::Bytes(self)
    }
}

impl BuildTokenValue for BuilderData {
    fn token_value(self) -> TokenValue {
        TokenValue::Cell(self.into())
    }
}

impl<T> BuildTokenValue for Maybe<T>
where
    T: BuildTokenValue + KnownParamType,
{
    fn token_value(self) -> TokenValue {
        TokenValue::Optional(
            T::param_type(),
            self.0.map(|item| Box::new(item.token_value())),
        )
    }
}

impl<T> BuildTokenValue for MaybeRef<T>
where
    T: BuildTokenValue + KnownParamType,
{
    fn token_value(self) -> TokenValue {
        TokenValue::Optional(
            ton_abi::ParamType::Ref(Box::new(T::param_type())),
            self.0
                .map(|item| Box::new(TokenValue::Ref(Box::new(item.token_value())))),
        )
    }
}

impl<T> BuildTokenValue for Vec<T>
where
    T: StandaloneToken + KnownParamType + BuildTokenValue,
{
    fn token_value(self) -> TokenValue {
        TokenValue::Array(
            T::param_type(),
            self.into_iter().map(BuildTokenValue::token_value).collect(),
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maybe_ref_serialization() {
        // Some
        let value = ton_abi::TokenValue::pack_token_values_into_chain(
            &[MaybeRef(Some(123u32)).token_value()],
            Default::default(),
            ton_abi::contract::ABI_VERSION_2_2,
        )
        .unwrap()
        .into_cell()
        .unwrap();

        let serialized = base64::encode(ton_types::serialize_toc(&value).unwrap());
        assert_eq!(serialized, "te6ccgEBAgEACgABAcABAAgAAAB7");

        // None
        let value = ton_abi::TokenValue::pack_token_values_into_chain(
            &[MaybeRef(Option::<u32>::None).token_value()],
            Default::default(),
            ton_abi::contract::ABI_VERSION_2_2,
        )
        .unwrap()
        .into_cell()
        .unwrap();

        let serialized = base64::encode(ton_types::serialize_toc(&value).unwrap());
        assert_eq!(serialized, "te6ccgEBAQEAAwAAAUA=");
    }
}
