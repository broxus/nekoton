pub use num_traits;

use num_traits::ToPrimitive;
use ton_abi::{Token, TokenValue};
use ton_block::{MsgAddrStd, MsgAddressInt};
use ton_types::{Cell, UInt256};

pub trait IgnoreOutput: Sized {
    fn ignore_output(self) -> Result<(), UnpackerError> {
        Ok(())
    }
}

impl IgnoreOutput for Vec<Token> {}

pub trait IntoUnpacker: Sized {
    type Iter: Iterator<Item = Token>;

    fn into_unpacker(self) -> ContractOutputUnpacker<Self::Iter>;
}

impl IntoUnpacker for Vec<Token> {
    type Iter = std::vec::IntoIter<Token>;

    fn into_unpacker(self) -> ContractOutputUnpacker<Self::Iter> {
        ContractOutputUnpacker(self.into_iter())
    }
}

#[derive(Debug)]
pub struct ContractOutputUnpacker<I>(I);

impl<I: Iterator<Item = Token>> ContractOutputUnpacker<I> {
    pub fn unpack_next<T>(&mut self) -> ContractResult<T>
    where
        TokenValue: UnpackToken<T>,
    {
        self.0.next().unpack()
    }
}

pub trait UnpackToken<T> {
    fn unpack(self) -> ContractResult<T>;
}

impl UnpackToken<MsgAddrStd> for TokenValue {
    fn unpack(self) -> ContractResult<MsgAddrStd> {
        match self {
            TokenValue::Address(ton_block::MsgAddress::AddrStd(address)) => Ok(address),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<MsgAddressInt> for TokenValue {
    fn unpack(self) -> ContractResult<MsgAddressInt> {
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

impl UnpackToken<Cell> for TokenValue {
    fn unpack(self) -> ContractResult<Cell> {
        match self {
            TokenValue::Cell(cell) => Ok(cell),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<Vec<u8>> for TokenValue {
    fn unpack(self) -> ContractResult<Vec<u8>> {
        match self {
            TokenValue::Bytes(bytes) => Ok(bytes),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<String> for TokenValue {
    fn unpack(self) -> ContractResult<String> {
        match self {
            TokenValue::Bytes(bytes) => {
                String::from_utf8(bytes).map_err(|_| UnpackerError::InvalidAbi)
            }
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<UInt256> for TokenValue {
    fn unpack(self) -> ContractResult<UInt256> {
        match self {
            TokenValue::Uint(data) => {
                let mut result = [0; 32];
                let data = data.number.to_bytes_be();

                let len = std::cmp::min(data.len(), 32);
                let offset = 32 - len;
                (0..len).for_each(|i| result[i + offset] = data[i]);

                Ok(result.into())
            }
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<i8> for TokenValue {
    fn unpack(self) -> ContractResult<i8> {
        match self {
            TokenValue::Int(data) => Ok(data.number.to_i8().ok_or(UnpackerError::InvalidAbi)?),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<u8> for TokenValue {
    fn unpack(self) -> ContractResult<u8> {
        match self {
            TokenValue::Uint(data) => Ok(data.number.to_u8().ok_or(UnpackerError::InvalidAbi)?),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<u16> for TokenValue {
    fn unpack(self) -> ContractResult<u16> {
        match self {
            TokenValue::Uint(data) => Ok(data.number.to_u16().ok_or(UnpackerError::InvalidAbi)?),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<u32> for TokenValue {
    fn unpack(self) -> ContractResult<u32> {
        match self {
            TokenValue::Uint(data) => Ok(data.number.to_u32().ok_or(UnpackerError::InvalidAbi)?),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<u64> for TokenValue {
    fn unpack(self) -> ContractResult<u64> {
        match self {
            TokenValue::Uint(data) => Ok(data.number.to_u64().ok_or(UnpackerError::InvalidAbi)?),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<u128> for TokenValue {
    fn unpack(self) -> ContractResult<u128> {
        match self {
            TokenValue::Uint(data) => Ok(data.number.to_u128().ok_or(UnpackerError::InvalidAbi)?),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<bool> for TokenValue {
    fn unpack(self) -> ContractResult<bool> {
        match self {
            TokenValue::Bool(confirmed) => Ok(confirmed),
            _ => Err(UnpackerError::InvalidAbi),
        }
    }
}

impl UnpackToken<TokenValue> for TokenValue {
    #[inline]
    fn unpack(self) -> ContractResult<TokenValue> {
        Ok(self)
    }
}

impl<T> UnpackToken<T> for Option<Token>
where
    TokenValue: UnpackToken<T>,
{
    fn unpack(self) -> ContractResult<T> {
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
    fn unpack(self) -> ContractResult<T> {
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
    fn unpack(self) -> ContractResult<Vec<T>> {
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
    fn unpack(self) -> ContractResult<T> {
        self.value.unpack()
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

pub type ContractResult<T> = Result<T, UnpackerError>;

#[derive(thiserror::Error, Debug, Clone)]
pub enum UnpackerError {
    #[error("Invalid ABI")]
    InvalidAbi,
    #[error("Invalid name (expected {expected:?}, found {found:?})")]
    InvalidName { expected: String, found: String },
}
