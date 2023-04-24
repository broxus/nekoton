use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;

use num_bigint::{BigInt, BigUint};
use ton_abi::{MapKeyTokenValue, Token, TokenValue};
use ton_block::{MsgAddrStd, MsgAddress, MsgAddressInt};
use ton_types::{BuilderData, Cell};

use super::{KnownParamType, MaybeRef, StandaloneToken};

pub trait PackAbiPlain {
    fn pack(self) -> Vec<Token>;
}

pub trait PackAbi: BuildTokenValue {
    fn pack(self) -> TokenValue;
}

pub trait BuildTokenValue {
    fn token_value(self) -> TokenValue;
}

pub trait BuildMapKeyTokenValue {
    fn map_key_token_value(self) -> MapKeyTokenValue;
}

macro_rules! impl_integer {
    ($int:ty, $abi:ident, $bigint:ident, $size:literal) => {
        impl BuildTokenValue for $int {
            fn token_value(self) -> TokenValue {
                self.map_key_token_value().into()
            }
        }

        impl BuildMapKeyTokenValue for $int {
            fn map_key_token_value(self) -> MapKeyTokenValue {
                MapKeyTokenValue::$abi(ton_abi::$abi {
                    number: $bigint::from(self),
                    size: $size,
                })
            }
        }
    };
}

impl_integer!(i8, Int, BigInt, 8);
impl_integer!(u8, Uint, BigUint, 8);
impl_integer!(i16, Int, BigInt, 16);
impl_integer!(u16, Uint, BigUint, 16);
impl_integer!(i32, Int, BigInt, 32);
impl_integer!(u32, Uint, BigUint, 32);
impl_integer!(i64, Int, BigInt, 64);
impl_integer!(u64, Uint, BigUint, 64);
impl_integer!(i128, Int, BigInt, 128);
impl_integer!(u128, Uint, BigUint, 128);

impl BuildTokenValue for ton_types::UInt256 {
    fn token_value(self) -> TokenValue {
        self.map_key_token_value().into()
    }
}

impl BuildMapKeyTokenValue for ton_types::UInt256 {
    fn map_key_token_value(self) -> MapKeyTokenValue {
        MapKeyTokenValue::Uint(ton_abi::Uint {
            number: BigUint::from_bytes_be(self.as_slice()),
            size: 256,
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
        self.map_key_token_value().into()
    }
}

impl BuildMapKeyTokenValue for MsgAddressInt {
    fn map_key_token_value(self) -> MapKeyTokenValue {
        MapKeyTokenValue::Address(match self {
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

impl BuildMapKeyTokenValue for MsgAddrStd {
    fn map_key_token_value(self) -> MapKeyTokenValue {
        MapKeyTokenValue::Address(MsgAddress::AddrStd(self))
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
        TokenValue::Cell(self.into_cell().unwrap())
    }
}

impl<T> BuildTokenValue for Option<T>
where
    T: BuildTokenValue + KnownParamType,
{
    fn token_value(self) -> TokenValue {
        TokenValue::Optional(
            T::param_type(),
            self.map(|item| Box::new(item.token_value())),
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

impl<K, V> BuildTokenValue for BTreeMap<K, V>
where
    K: KnownParamType + BuildMapKeyTokenValue,
    V: KnownParamType + BuildTokenValue,
{
    fn token_value(self) -> TokenValue {
        let mut map = BTreeMap::new();
        for (k, v) in self {
            map.insert(k.map_key_token_value(), v.token_value());
        }
        TokenValue::Map(K::param_type(), V::param_type(), map)
    }
}

impl<K, V, S> BuildTokenValue for HashMap<K, V, S>
where
    K: KnownParamType + BuildMapKeyTokenValue,
    V: KnownParamType + BuildTokenValue,
    S: BuildHasher,
{
    fn token_value(self) -> TokenValue {
        let mut map = BTreeMap::new();
        for (k, v) in self {
            map.insert(k.map_key_token_value(), v.token_value());
        }
        TokenValue::Map(K::param_type(), V::param_type(), map)
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
