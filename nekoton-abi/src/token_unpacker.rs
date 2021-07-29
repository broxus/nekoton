use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;
use ton_abi::{Token, TokenValue};
use ton_block::{MsgAddrStd, MsgAddressInt};
use ton_types::Cell;

use super::StandaloneToken;

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

pub trait IntoUnpacker {
    type Iter: Iterator<Item = Token>;

    fn into_unpacker(self) -> ContractOutputUnpacker<Self::Iter>;
}

impl IntoUnpacker for Vec<Token> {
    type Iter = std::vec::IntoIter<Token>;

    fn into_unpacker(self) -> ContractOutputUnpacker<Self::Iter> {
        ContractOutputUnpacker(self.into_iter())
    }
}

pub trait UnpackFirst {
    fn unpack_first<T>(self) -> UnpackerResult<T>
    where
        TokenValue: UnpackToken<T>;
}

impl UnpackFirst for Vec<Token> {
    fn unpack_first<T>(self) -> UnpackerResult<T>
    where
        TokenValue: UnpackToken<T>,
    {
        self.into_unpacker().unpack_next()
    }
}

#[derive(Debug)]
pub struct ContractOutputUnpacker<I>(I);

impl<I: Iterator<Item = Token>> ContractOutputUnpacker<I> {
    pub fn unpack_next<T>(&mut self) -> UnpackerResult<T>
    where
        TokenValue: UnpackToken<T>,
    {
        self.0.next().unpack()
    }
}

pub trait UnpackToken<T> {
    fn unpack(self) -> UnpackerResult<T>;
}

impl UnpackToken<i8> for TokenValue {
    fn unpack(self) -> UnpackerResult<i8> {
        UnpackToken::<BigInt>::unpack(self)?
            .to_i8()
            .ok_or(UnpackerError::InvalidAbi)
    }
}

impl UnpackToken<u8> for TokenValue {
    fn unpack(self) -> UnpackerResult<u8> {
        UnpackToken::<BigUint>::unpack(self)?
            .to_u8()
            .ok_or(UnpackerError::InvalidAbi)
    }
}

impl UnpackToken<u16> for TokenValue {
    fn unpack(self) -> UnpackerResult<u16> {
        UnpackToken::<BigUint>::unpack(self)?
            .to_u16()
            .ok_or(UnpackerError::InvalidAbi)
    }
}

impl UnpackToken<u32> for TokenValue {
    fn unpack(self) -> UnpackerResult<u32> {
        UnpackToken::<BigUint>::unpack(self)?
            .to_u32()
            .ok_or(UnpackerError::InvalidAbi)
    }
}

impl UnpackToken<u64> for TokenValue {
    fn unpack(self) -> UnpackerResult<u64> {
        UnpackToken::<BigUint>::unpack(self)?
            .to_u64()
            .ok_or(UnpackerError::InvalidAbi)
    }
}

impl UnpackToken<u128> for TokenValue {
    fn unpack(self) -> UnpackerResult<u128> {
        UnpackToken::<BigUint>::unpack(self)?
            .to_u128()
            .ok_or(UnpackerError::InvalidAbi)
    }
}

impl UnpackToken<bool> for TokenValue {
    fn unpack(self) -> UnpackerResult<bool> {
        match self {
            TokenValue::Bool(confirmed) => Ok(confirmed),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<Cell> for TokenValue {
    fn unpack(self) -> UnpackerResult<Cell> {
        match self {
            TokenValue::Cell(cell) => Ok(cell),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<MsgAddressInt> for TokenValue {
    fn unpack(self) -> UnpackerResult<MsgAddressInt> {
        match self {
            TokenValue::Address(ton_block::MsgAddress::AddrStd(addr)) => {
                Ok(MsgAddressInt::AddrStd(addr))
            }
            TokenValue::Address(ton_block::MsgAddress::AddrVar(addr)) => {
                Ok(MsgAddressInt::AddrVar(addr))
            }
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<MsgAddrStd> for TokenValue {
    fn unpack(self) -> UnpackerResult<MsgAddrStd> {
        match self {
            TokenValue::Address(ton_block::MsgAddress::AddrStd(addr)) => Ok(addr),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<String> for TokenValue {
    fn unpack(self) -> UnpackerResult<String> {
        match self {
            TokenValue::Bytes(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<BigInt> for TokenValue {
    fn unpack(self) -> UnpackerResult<BigInt> {
        match self {
            TokenValue::Int(data) => Ok(data.number),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<BigUint> for TokenValue {
    fn unpack(self) -> UnpackerResult<BigUint> {
        match self {
            TokenValue::Uint(data) => Ok(data.number),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<Vec<u8>> for TokenValue {
    fn unpack(self) -> UnpackerResult<Vec<u8>> {
        match self {
            TokenValue::Bytes(bytes) => Ok(bytes),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<TokenValue> for TokenValue {
    #[inline]
    fn unpack(self) -> UnpackerResult<TokenValue> {
        Ok(self)
    }
}

impl<T> UnpackToken<T> for Option<Token>
where
    TokenValue: UnpackToken<T>,
{
    fn unpack(self) -> UnpackerResult<T> {
        match self {
            Some(token) => token.value.unpack(),
            None => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl<T> UnpackToken<T> for Option<TokenValue>
where
    TokenValue: UnpackToken<T>,
{
    fn unpack(self) -> UnpackerResult<T> {
        match self {
            Some(value) => value.unpack(),
            None => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl<T> UnpackToken<Vec<T>> for TokenValue
where
    T: StandaloneToken,
    TokenValue: UnpackToken<T>,
{
    fn unpack(self) -> UnpackerResult<Vec<T>> {
        match self {
            TokenValue::Array(tokens) | TokenValue::FixedArray(tokens) => tokens,
            _ => return Err(UnpackerError::InvalidAbi),
        }
        .into_iter()
        .map(UnpackToken::unpack)
        .collect()
    }
}

impl<T> UnpackToken<T> for Token
where
    TokenValue: UnpackToken<T>,
{
    fn unpack(self) -> UnpackerResult<T> {
        self.value.unpack()
    }
}

pub type UnpackerResult<T> = Result<T, UnpackerError>;

#[derive(thiserror::Error, Debug, Clone)]
pub enum UnpackerError {
    #[error("Invalid ABI")]
    InvalidAbi,
    #[error("Invalid name (expected {expected:?}, found {found:?})")]
    InvalidName { expected: String, found: String },
}
