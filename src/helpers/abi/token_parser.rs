use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;
use ton_abi::{Token, TokenValue};
use ton_block::{MsgAddrStd, MsgAddressInt};
use ton_types::{Cell, UInt256};

use super::StandaloneToken;
use crate::utils::*;

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
    fn ignore_output(self) -> Result<(), ParserError> {
        Ok(())
    }
}

impl IgnoreOutput for Vec<Token> {}

pub trait IntoParser: Sized {
    type Iter: Iterator<Item = Token>;

    fn into_parser(self) -> ContractOutputParser<Self::Iter>;
}

impl IntoParser for Vec<Token> {
    type Iter = std::vec::IntoIter<Token>;

    fn into_parser(self) -> ContractOutputParser<Self::Iter> {
        ContractOutputParser(self.into_iter())
    }
}

#[derive(Debug)]
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
            _ => Err(ParserError::InvalidAbi),
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
            _ => Err(ParserError::InvalidAbi),
        }
    }
}

impl ParseToken<Cell> for TokenValue {
    fn try_parse(self) -> ContractResult<Cell> {
        match self {
            TokenValue::Cell(cell) => Ok(cell),
            _ => Err(ParserError::InvalidAbi),
        }
    }
}

impl ParseToken<Vec<u8>> for TokenValue {
    fn try_parse(self) -> ContractResult<Vec<u8>> {
        match self {
            TokenValue::Bytes(bytes) => Ok(bytes),
            _ => Err(ParserError::InvalidAbi),
        }
    }
}

impl ParseToken<String> for TokenValue {
    fn try_parse(self) -> ContractResult<String> {
        match self {
            TokenValue::Bytes(bytes) => {
                String::from_utf8(bytes).map_err(|_| ParserError::InvalidAbi)
            }
            _ => Err(ParserError::InvalidAbi),
        }
    }
}

impl ParseToken<BigUint> for TokenValue {
    fn try_parse(self) -> ContractResult<BigUint> {
        match self {
            TokenValue::Uint(data) => Ok(data.number),
            _ => Err(ParserError::InvalidAbi),
        }
    }
}

impl ParseToken<BigInt> for TokenValue {
    fn try_parse(self) -> ContractResult<BigInt> {
        match self {
            TokenValue::Int(data) => Ok(data.number),
            _ => Err(ParserError::InvalidAbi),
        }
    }
}

impl ParseToken<UInt256> for TokenValue {
    fn try_parse(self) -> ContractResult<UInt256> {
        match self {
            TokenValue::Uint(data) => {
                let mut result = [0; 32];
                let data = data.number.to_bytes_be();

                let len = std::cmp::min(data.len(), 32);
                let offset = 32 - len;
                (0..len).for_each(|i| result[i + offset] = data[i]);

                Ok(result.into())
            }
            _ => Err(ParserError::InvalidAbi),
        }
    }
}

impl ParseToken<UInt128> for TokenValue {
    fn try_parse(self) -> ContractResult<UInt128> {
        match self {
            TokenValue::Uint(data) => Ok(data.number.to_bytes_be().into()),
            _ => Err(ParserError::InvalidAbi),
        }
    }
}

impl ParseToken<i8> for TokenValue {
    fn try_parse(self) -> ContractResult<i8> {
        ParseToken::<BigInt>::try_parse(self)?
            .to_i8()
            .ok_or(ParserError::InvalidAbi)
    }
}

impl ParseToken<u8> for TokenValue {
    fn try_parse(self) -> ContractResult<u8> {
        ParseToken::<BigUint>::try_parse(self)?
            .to_u8()
            .ok_or(ParserError::InvalidAbi)
    }
}

impl ParseToken<u16> for TokenValue {
    fn try_parse(self) -> ContractResult<u16> {
        ParseToken::<BigUint>::try_parse(self)?
            .to_u16()
            .ok_or(ParserError::InvalidAbi)
    }
}

impl ParseToken<u32> for TokenValue {
    fn try_parse(self) -> ContractResult<u32> {
        ParseToken::<BigUint>::try_parse(self)?
            .to_u32()
            .ok_or(ParserError::InvalidAbi)
    }
}

impl ParseToken<u64> for TokenValue {
    fn try_parse(self) -> ContractResult<u64> {
        ParseToken::<BigUint>::try_parse(self)?
            .to_u64()
            .ok_or(ParserError::InvalidAbi)
    }
}

impl ParseToken<bool> for TokenValue {
    fn try_parse(self) -> ContractResult<bool> {
        match self {
            TokenValue::Bool(confirmed) => Ok(confirmed),
            _ => Err(ParserError::InvalidAbi),
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
            None => Err(ParserError::InvalidAbi),
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
            None => Err(ParserError::InvalidAbi),
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
            _ => return Err(ParserError::InvalidAbi),
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

pub type ContractResult<T> = Result<T, ParserError>;

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum ParserError {
    #[error("Invalid ABI")]
    InvalidAbi,
}
