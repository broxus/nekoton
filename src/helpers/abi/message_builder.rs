use anyhow::Result;
use num_bigint::{BigInt, BigUint};
use ton_abi::{Contract, Function, Token, TokenValue};
use ton_block::{MsgAddrStd, MsgAddress, MsgAddressInt};
use ton_types::{BuilderData, UInt256};

use super::StandaloneToken;
use crate::utils::*;

pub struct MessageBuilder<'a> {
    function: &'a Function,
    inputs: Vec<Token>,
}

impl<'a> MessageBuilder<'a> {
    pub fn new(contract: &'a Contract, function_name: &str) -> Result<Self> {
        let function = contract
            .function(function_name)
            .map_err(|_| BuilderError::InvalidAbi)?;
        let input = Vec::with_capacity(function.inputs.len());

        Ok(Self {
            function,
            inputs: input,
        })
    }

    pub fn arg<A>(mut self, value: A) -> Self
    where
        A: FunctionArg,
    {
        let name = &self.function.inputs[self.inputs.len()].name;
        self.inputs.push(Token::new(name, value.token_value()));
        self
    }

    pub fn args<A>(mut self, values: A) -> Self
    where
        A: FunctionArgsGroup,
    {
        let token_values = values.token_values();
        let args_from = self.inputs.len();
        let args_to = args_from + token_values.len();

        let inputs = &self.function.inputs;
        self.inputs.extend(
            (args_from..args_to)
                .into_iter()
                .map(|i| inputs[i].name.as_ref())
                .zip(token_values.into_iter())
                .map(|(name, value)| Token::new(name, value)),
        );
        self
    }

    pub fn build(self) -> (&'a Function, Vec<Token>) {
        (self.function, self.inputs)
    }
}

impl FunctionArg for bool {
    fn token_value(self) -> TokenValue {
        TokenValue::Bool(self)
    }
}

impl FunctionArg for &str {
    fn token_value(self) -> TokenValue {
        TokenValue::Bytes(self.as_bytes().into())
    }
}

impl FunctionArg for Vec<u8> {
    fn token_value(self) -> TokenValue {
        TokenValue::Bytes(self)
    }
}

impl FunctionArg for MsgAddrStd {
    fn token_value(self) -> TokenValue {
        TokenValue::Address(MsgAddress::AddrStd(self))
    }
}

impl FunctionArg for MsgAddressInt {
    fn token_value(self) -> TokenValue {
        TokenValue::Address(match self {
            MsgAddressInt::AddrStd(addr) => MsgAddress::AddrStd(addr),
            MsgAddressInt::AddrVar(addr) => MsgAddress::AddrVar(addr),
        })
    }
}

impl FunctionArg for UInt256 {
    fn token_value(self) -> TokenValue {
        BigUint256(num_bigint::BigUint::from_bytes_be(self.as_slice())).token_value()
    }
}

impl FunctionArg for UInt128 {
    fn token_value(self) -> TokenValue {
        BigUint128(num_bigint::BigUint::from_bytes_be(self.as_slice())).token_value()
    }
}

pub struct BigUint256(pub BigUint);

impl FunctionArg for BigUint256 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: self.0,
            size: 256,
        })
    }
}

pub struct BigUint128(pub BigUint);

impl FunctionArg for BigUint128 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: self.0,
            size: 128,
        })
    }
}

impl FunctionArg for i8 {
    fn token_value(self) -> TokenValue {
        TokenValue::Int(ton_abi::Int {
            number: BigInt::from(self),
            size: 8,
        })
    }
}

impl FunctionArg for u8 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from(self),
            size: 8,
        })
    }
}

impl FunctionArg for u16 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from(self),
            size: 16,
        })
    }
}

impl FunctionArg for u32 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from(self),
            size: 32,
        })
    }
}

impl FunctionArg for u64 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: BigUint::from(self),
            size: 64,
        })
    }
}

impl FunctionArg for BuilderData {
    fn token_value(self) -> TokenValue {
        TokenValue::Cell(self.into())
    }
}

impl FunctionArg for ton_types::Cell {
    fn token_value(self) -> TokenValue {
        TokenValue::Cell(self)
    }
}

impl<T> FunctionArg for Vec<T>
where
    T: StandaloneToken + FunctionArg,
{
    fn token_value(self) -> TokenValue {
        TokenValue::Array(self.into_iter().map(FunctionArg::token_value).collect())
    }
}

impl FunctionArg for TokenValue {
    fn token_value(self) -> TokenValue {
        self
    }
}

impl<T> FunctionArg for &T
where
    T: Clone + FunctionArg,
{
    fn token_value(self) -> TokenValue {
        self.clone().token_value()
    }
}

impl<T> FunctionArgsGroup for &T
where
    T: Clone + FunctionArgsGroup,
{
    fn token_values(self) -> Vec<TokenValue> {
        self.clone().token_values()
    }
}

pub trait FunctionArg {
    fn token_value(self) -> TokenValue;
}

pub trait FunctionArgsGroup {
    fn token_values(self) -> Vec<TokenValue>;
}

#[derive(thiserror::Error, Debug)]
enum BuilderError {
    #[error("Invalid ABI")]
    InvalidAbi,
}
