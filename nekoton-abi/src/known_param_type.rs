use ton_abi::{Param, ParamType};
use ton_block::{MsgAddrStd, MsgAddressInt};
use ton_types::{BuilderData, Cell};

use super::{Maybe, MaybeRef, StandaloneToken};

pub trait KnownParamTypePlain {
    fn param_type() -> Vec<Param>;
}

pub trait KnownParamType {
    fn param_type() -> ParamType;
}

impl<T> KnownParamType for &T
where
    T: KnownParamType,
{
    fn param_type() -> ParamType {
        T::param_type()
    }
}

pub trait KnownParamTypeArray<I: KnownParamType> {
    fn item_param_type() -> ParamType {
        I::param_type()
    }
}

impl<T, I> KnownParamTypeArray<I> for T
where
    T: AsRef<[I]>,
    I: KnownParamType,
{
}

impl KnownParamType for i8 {
    fn param_type() -> ParamType {
        ParamType::Int(8)
    }
}

impl KnownParamType for u8 {
    fn param_type() -> ParamType {
        ParamType::Uint(8)
    }
}

impl KnownParamType for i16 {
    fn param_type() -> ParamType {
        ParamType::Int(16)
    }
}

impl KnownParamType for u16 {
    fn param_type() -> ParamType {
        ParamType::Uint(16)
    }
}

impl KnownParamType for i32 {
    fn param_type() -> ParamType {
        ParamType::Int(32)
    }
}

impl KnownParamType for u32 {
    fn param_type() -> ParamType {
        ParamType::Uint(32)
    }
}

impl KnownParamType for i64 {
    fn param_type() -> ParamType {
        ParamType::Int(64)
    }
}

impl KnownParamType for u64 {
    fn param_type() -> ParamType {
        ParamType::Uint(64)
    }
}

impl KnownParamType for i128 {
    fn param_type() -> ParamType {
        ParamType::Int(128)
    }
}

impl KnownParamType for u128 {
    fn param_type() -> ParamType {
        ParamType::Uint(128)
    }
}

impl KnownParamType for bool {
    fn param_type() -> ParamType {
        ParamType::Bool
    }
}

impl KnownParamType for Cell {
    fn param_type() -> ParamType {
        ParamType::Cell
    }
}

impl KnownParamType for MsgAddressInt {
    fn param_type() -> ParamType {
        ParamType::Address
    }
}

impl KnownParamType for MsgAddrStd {
    fn param_type() -> ParamType {
        ParamType::Address
    }
}

impl KnownParamType for &str {
    fn param_type() -> ParamType {
        ParamType::Bytes
    }
}

impl KnownParamType for ton_block::Grams {
    fn param_type() -> ParamType {
        ParamType::Token
    }
}

impl KnownParamType for Vec<u8> {
    fn param_type() -> ParamType {
        ParamType::Bytes
    }
}

impl KnownParamType for BuilderData {
    fn param_type() -> ParamType {
        ParamType::Cell
    }
}

impl<T> KnownParamType for Maybe<T>
where
    T: StandaloneToken + KnownParamType,
{
    fn param_type() -> ParamType {
        ParamType::Optional(Box::new(T::param_type()))
    }
}

impl<T> KnownParamType for MaybeRef<T>
where
    T: StandaloneToken + KnownParamType,
{
    fn param_type() -> ParamType {
        ParamType::Optional(Box::new(ParamType::Ref(Box::new(T::param_type()))))
    }
}

impl<T> KnownParamType for Vec<T>
where
    T: StandaloneToken + KnownParamType,
{
    fn param_type() -> ParamType {
        ParamType::Array(Box::new(T::param_type()))
    }
}
