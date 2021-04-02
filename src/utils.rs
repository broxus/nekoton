use std::fmt::{LowerHex, UpperHex};
use std::str::FromStr;

use anyhow::Error;
use ton_types::SliceData;

pub trait NoFailure {
    type Output;
    fn convert(self) -> Result<Self::Output, Error>;
}

impl<T> NoFailure for Result<T, failure::Error> {
    type Output = T;
    fn convert(self) -> Result<Self::Output, Error> {
        self.map_err(|e| Error::msg(e.to_string()))
    }
}

pub trait TrustMe<T>: Sized {
    #[track_caller]
    fn trust_me(self) -> T;
}

impl<T, E> TrustMe<T> for Result<T, E>
where
    E: std::fmt::Debug,
{
    #[track_caller]
    fn trust_me(self) -> T {
        self.expect("Shouldn't fail")
    }
}

impl<T> TrustMe<T> for Option<T> {
    #[track_caller]
    fn trust_me(self) -> T {
        self.expect("Shouldn't fail")
    }
}

#[allow(clippy::derive_hash_xor_eq)]
#[derive(Clone, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct UInt128([u8; 16]);

impl PartialEq<SliceData> for UInt128 {
    fn eq(&self, other: &SliceData) -> bool {
        if other.remaining_bits() == 128 {
            return self.0 == other.get_bytestring(0).as_slice();
        }
        false
    }
}

impl PartialEq<UInt128> for &UInt128 {
    fn eq(&self, other: &UInt128) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<&UInt128> for UInt128 {
    fn eq(&self, other: &&UInt128) -> bool {
        self.0 == other.0
    }
}

impl UInt128 {
    pub fn is_zero(&self) -> bool {
        for b in &self.0 {
            if b != &0 {
                return false;
            }
        }
        true
    }

    pub fn as_slice(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex_string(&self) -> String {
        hex::encode(self.0)
    }

    pub fn max() -> Self {
        UInt128([0xFF; 16])
    }

    pub const MIN: UInt128 = UInt128([0; 16]);
    pub const MAX: UInt128 = UInt128([0xFF; 16]);
}

impl FromStr for UInt128 {
    type Err = failure::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 32 {
            ton_types::fail!("invalid account ID string length (32 expected)")
        } else {
            let bytes = hex::decode(value)?;
            Ok(UInt128::from(bytes))
        }
    }
}

impl From<[u8; 16]> for UInt128 {
    fn from(data: [u8; 16]) -> Self {
        UInt128(data)
    }
}

impl From<UInt128> for [u8; 16] {
    fn from(data: UInt128) -> Self {
        data.0
    }
}

impl<'a> From<&'a UInt128> for &'a [u8; 16] {
    fn from(data: &'a UInt128) -> Self {
        &data.0
    }
}

impl<'a> From<&'a [u8; 16]> for UInt128 {
    fn from(data: &[u8; 16]) -> Self {
        UInt128(*data)
    }
}

impl From<&[u8]> for UInt128 {
    fn from(value: &[u8]) -> Self {
        let mut data = [0; 16];
        let len = std::cmp::min(value.len(), 16);
        (0..len).for_each(|i| data[i] = value[i]);
        Self(data)
    }
}

impl From<Vec<u8>> for UInt128 {
    fn from(value: Vec<u8>) -> Self {
        UInt128::from(value.as_slice())
    }
}

impl std::fmt::Debug for UInt128 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        LowerHex::fmt(self, f)
    }
}

impl std::fmt::Display for UInt128 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "UInt128[{:X?}]", self.as_slice())
    }
}

impl LowerHex for UInt128 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl UpperHex for UInt128 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        write!(f, "{}", hex::encode_upper(&self.0))
    }
}

impl std::convert::AsRef<[u8]> for &UInt128 {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[macro_export]
macro_rules! define_string_enum {
    ($vis:vis enum $type:ident { $($variant:ident),*$(,)? }) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
        $vis enum $type {
            $($variant),*,
        }

        impl std::str::FromStr for $type {
            type Err = anyhow::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(match s {
                    $(stringify!($variant) => Self::$variant),*,
                    _ => return Err($crate::utils::UnknownEnumVariant.into()),
                })
            }
        }

        impl std::fmt::Display for $type {
            fn fmt(&self, f: &'_ mut std::fmt::Formatter) -> std::fmt::Result {
                match self {
                    $(Self::$variant => f.write_str(stringify!($variant))),*,
                }
            }
        }
    };
}

#[derive(thiserror::Error, Debug)]
#[error("Unknown enum variant")]
pub struct UnknownEnumVariant;
