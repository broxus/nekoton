use anyhow::Result;
use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;
use ton_abi::{Contract, Function, Token, TokenValue};
use ton_block::{MsgAddrStd, MsgAddress, MsgAddressInt};
use ton_types::{BuilderData, Cell, UInt256};
pub mod functions;
use crate::utils::*;

#[derive(thiserror::Error, Debug)]
pub enum ContractError {
    #[error("Invalid ABI")]
    InvalidAbi,
}

pub struct MessageBuilder<'a> {
    function: &'a Function,
    inputs: Vec<Token>,
}

impl<'a> MessageBuilder<'a> {
    pub fn new(contract: &'a Contract, function_name: &str) -> Result<Self> {
        let function = contract
            .function(function_name)
            .map_err(|_| ContractError::InvalidAbi)?;
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

pub trait TokenValueExt {
    fn unnamed(self) -> Token;

    fn named<T>(self, name: T) -> Token
    where
        T: ToString;
}

impl TokenValueExt for TokenValue {
    fn unnamed(self) -> Token {
        Token {
            name: String::new(),
            value: self,
        }
    }

    fn named<T>(self, name: T) -> Token
    where
        T: ToString,
    {
        Token {
            name: name.to_string(),
            value: self,
        }
    }
}

pub trait IgnoreOutput: Sized {
    fn ignore_output(self) -> Result<(), ContractError> {
        Ok(())
    }
}

impl IgnoreOutput for Vec<Token> {}

pub struct ContractOutputParser<I>(I);

impl<I: Iterator<Item = Token>> ContractOutputParser<I> {
    pub fn parse_next<T>(&mut self) -> ContractResult<T>
    where
        TokenValue: ParseToken<T>,
    {
        self.0.next().try_parse()
    }
}

pub trait ParseToken<T> {
    fn try_parse(self) -> ContractResult<T>;
}

impl ParseToken<MsgAddrStd> for TokenValue {
    fn try_parse(self) -> ContractResult<MsgAddrStd> {
        match self {
            TokenValue::Address(ton_block::MsgAddress::AddrStd(address)) => Ok(address),
            _ => Err(ContractError::InvalidAbi),
        }
    }
}

impl ParseToken<MsgAddressInt> for TokenValue {
    fn try_parse(self) -> ContractResult<MsgAddressInt> {
        match self {
            TokenValue::Address(ton_block::MsgAddress::AddrStd(addr)) => {
                Ok(MsgAddressInt::AddrStd(addr))
            }
            TokenValue::Address(ton_block::MsgAddress::AddrVar(addr)) => {
                Ok(MsgAddressInt::AddrVar(addr))
            }
            _ => Err(ContractError::InvalidAbi),
        }
    }
}

impl ParseToken<Cell> for TokenValue {
    fn try_parse(self) -> ContractResult<Cell> {
        match self {
            TokenValue::Cell(cell) => Ok(cell),
            _ => Err(ContractError::InvalidAbi),
        }
    }
}

impl ParseToken<Vec<u8>> for TokenValue {
    fn try_parse(self) -> ContractResult<Vec<u8>> {
        match self {
            TokenValue::Bytes(bytes) => Ok(bytes),
            _ => Err(ContractError::InvalidAbi),
        }
    }
}

impl ParseToken<String> for TokenValue {
    fn try_parse(self) -> ContractResult<String> {
        match self {
            TokenValue::Bytes(bytes) => {
                String::from_utf8(bytes).map_err(|_| ContractError::InvalidAbi)
            }
            _ => Err(ContractError::InvalidAbi),
        }
    }
}

impl ParseToken<BigUint> for TokenValue {
    fn try_parse(self) -> ContractResult<BigUint> {
        match self {
            TokenValue::Uint(data) => Ok(data.number),
            _ => Err(ContractError::InvalidAbi),
        }
    }
}

impl ParseToken<BigInt> for TokenValue {
    fn try_parse(self) -> ContractResult<BigInt> {
        match self {
            TokenValue::Int(data) => Ok(data.number),
            _ => Err(ContractError::InvalidAbi),
        }
    }
}

impl ParseToken<UInt256> for TokenValue {
    fn try_parse(self) -> ContractResult<UInt256> {
        match self {
            TokenValue::Uint(data) => Ok(data.number.to_bytes_be().into()),
            _ => Err(ContractError::InvalidAbi),
        }
    }
}

impl ParseToken<UInt128> for TokenValue {
    fn try_parse(self) -> ContractResult<UInt128> {
        match self {
            TokenValue::Uint(data) => Ok(data.number.to_bytes_be().into()),
            _ => Err(ContractError::InvalidAbi),
        }
    }
}

impl ParseToken<i8> for TokenValue {
    fn try_parse(self) -> ContractResult<i8> {
        ParseToken::<BigInt>::try_parse(self)?
            .to_i8()
            .ok_or(ContractError::InvalidAbi)
    }
}

impl ParseToken<u8> for TokenValue {
    fn try_parse(self) -> ContractResult<u8> {
        ParseToken::<BigUint>::try_parse(self)?
            .to_u8()
            .ok_or(ContractError::InvalidAbi)
    }
}

impl ParseToken<u16> for TokenValue {
    fn try_parse(self) -> ContractResult<u16> {
        ParseToken::<BigUint>::try_parse(self)?
            .to_u16()
            .ok_or(ContractError::InvalidAbi)
    }
}

impl ParseToken<u32> for TokenValue {
    fn try_parse(self) -> ContractResult<u32> {
        ParseToken::<BigUint>::try_parse(self)?
            .to_u32()
            .ok_or(ContractError::InvalidAbi)
    }
}

impl ParseToken<u64> for TokenValue {
    fn try_parse(self) -> ContractResult<u64> {
        ParseToken::<BigUint>::try_parse(self)?
            .to_u64()
            .ok_or(ContractError::InvalidAbi)
    }
}

impl ParseToken<bool> for TokenValue {
    fn try_parse(self) -> ContractResult<bool> {
        match self {
            TokenValue::Bool(confirmed) => Ok(confirmed),
            _ => Err(ContractError::InvalidAbi),
        }
    }
}

impl ParseToken<TokenValue> for TokenValue {
    #[inline]
    fn try_parse(self) -> ContractResult<TokenValue> {
        Ok(self)
    }
}

impl<T> ParseToken<T> for Option<Token>
where
    TokenValue: ParseToken<T>,
{
    fn try_parse(self) -> ContractResult<T> {
        match self {
            Some(token) => token.value.try_parse(),
            None => Err(ContractError::InvalidAbi),
        }
    }
}

impl<T> ParseToken<T> for Option<TokenValue>
where
    TokenValue: ParseToken<T>,
{
    fn try_parse(self) -> ContractResult<T> {
        match self {
            Some(value) => value.try_parse(),
            None => Err(ContractError::InvalidAbi),
        }
    }
}

impl<T> ParseToken<Vec<T>> for TokenValue
where
    T: StandaloneToken,
    TokenValue: ParseToken<T>,
{
    fn try_parse(self) -> ContractResult<Vec<T>> {
        match self {
            TokenValue::Array(tokens) | TokenValue::FixedArray(tokens) => tokens,
            _ => return Err(ContractError::InvalidAbi),
        }
        .into_iter()
        .map(ParseToken::try_parse)
        .collect()
    }
}

impl<T> ParseToken<T> for Token
where
    TokenValue: ParseToken<T>,
{
    fn try_parse(self) -> ContractResult<T> {
        self.value.try_parse()
    }
}

type ContractResult<T> = Result<T, ContractError>;

pub trait StandaloneToken {}
impl StandaloneToken for MsgAddressInt {}
impl StandaloneToken for MsgAddrStd {}
impl StandaloneToken for UInt256 {}
impl StandaloneToken for UInt128 {}
impl StandaloneToken for BigUint {}
impl StandaloneToken for BigInt {}
impl StandaloneToken for u16 {}
impl StandaloneToken for u32 {}
impl StandaloneToken for u64 {}
impl StandaloneToken for bool {}
impl StandaloneToken for Vec<u8> {}
impl StandaloneToken for TokenValue {}
