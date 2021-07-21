use anyhow::Result;
use num_bigint::{BigInt, BigUint};
use ton_abi::{Contract, Function, Token, TokenValue};
use ton_block::{MsgAddrStd, MsgAddress, MsgAddressInt};
use ton_types::{Cell, UInt256};

use super::StandaloneToken;

#[derive(Debug)]
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
        A: BuildTokenValue,
    {
        let name = &self.function.inputs[self.inputs.len()].name;
        self.inputs.push(Token::new(name, value.token_value()));
        self
    }

    pub fn args<A>(mut self, values: A) -> Self
    where
        A: BuildTokenValues,
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

#[derive(Debug)]
pub struct BigUint256(pub BigUint);

impl BuildTokenValue for BigUint256 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: self.0,
            size: 256,
        })
    }
}

#[derive(Debug)]
pub struct BigUint128(pub BigUint);

impl BuildTokenValue for BigUint128 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: self.0,
            size: 128,
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

#[derive(thiserror::Error, Debug)]
enum BuilderError {
    #[error("Invalid ABI")]
    InvalidAbi,
}
