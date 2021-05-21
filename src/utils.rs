use std::fmt::{LowerHex, UpperHex};
use std::str::FromStr;

use anyhow::Error;
use ton_block::MsgAddressInt;
use ton_types::{SliceData, UInt256};

pub const NONCE_LENGTH: usize = 12;

pub fn now() -> u32 {
    chrono::Utc::now().timestamp() as u32
}

pub fn read_u32(data: &ton_types::SliceData) -> ton_types::Result<u32> {
    let mut value: u32 = 0;
    for i in 0..4 {
        value |= (data.get_byte(8 * i)? as u32) << (8 * (3 - i));
    }
    Ok(value)
}

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
        let offset = 16 - len;
        (0..len).for_each(|i| data[i + offset] = value[i]);
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
    ($vis:vis enum $type:ident { $($(#[$inner:ident $($args:tt)*])* $variant:ident),*$(,)? }) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
        $vis enum $type {
            $($(#[$inner $($args)*])* $variant),*,
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

pub mod serde_public_key {
    use serde::de::Error;
    use serde::Deserialize;

    pub fn serialize<S>(data: &ed25519_dalek::PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(data.as_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ed25519_dalek::PublicKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?;
        let bytes = hex::decode(&data).map_err(|_| D::Error::custom("Invalid PublicKey"))?;
        ed25519_dalek::PublicKey::from_bytes(&bytes)
            .map_err(|_| D::Error::custom("Invalid PublicKey"))
    }
}

pub mod serde_uint256 {
    use super::*;

    use serde::de::Error;
    use serde::Deserialize;

    pub fn serialize<S>(data: &UInt256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&data.to_hex_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<UInt256, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?;
        UInt256::from_str(&data).map_err(|_| D::Error::custom("Invalid uint256"))
    }
}

pub mod serde_address {
    use super::*;

    use std::str::FromStr;

    use serde::de::Error;
    use serde::Deserialize;

    pub fn serialize<S>(data: &MsgAddressInt, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&data.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<MsgAddressInt, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?;
        MsgAddressInt::from_str(&data).map_err(|_| D::Error::custom("Invalid address"))
    }
}

pub mod serde_optional_address {
    use super::*;

    use serde::{Deserialize, Serialize};

    pub fn serialize<S>(data: &Option<MsgAddressInt>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(transparent)]
        struct Wrapper<'a>(#[serde(with = "serde_address")] &'a MsgAddressInt);

        match data {
            Some(data) => serializer.serialize_some(&Wrapper(data)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<MsgAddressInt>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct Wrapper(#[serde(with = "serde_address")] MsgAddressInt);

        Option::<Wrapper>::deserialize(deserializer).map(|wrapper| wrapper.map(|data| data.0))
    }
}

pub mod serde_bytes {
    pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]> + Sized,
        S: serde::Serializer,
    {
        serializer.serialize_str(&*hex::encode(&data.as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        <String as serde::Deserialize>::deserialize(deserializer)
            .and_then(|string| hex::decode(string).map_err(|e| D::Error::custom(e.to_string())))
    }
}

pub mod serde_nonce {
    use chacha20poly1305::Nonce;

    use super::*;

    pub fn serialize<S>(data: &Nonce, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::serialize(data, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Nonce, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde_bytes::deserialize(deserializer).and_then(|x| {
            if x.len() != NONCE_LENGTH {
                Err(serde::de::Error::custom(format!(
                    "Bad nonce len: {}, expected: 12",
                    x.len()
                )))
            } else {
                Ok(Nonce::clone_from_slice(&x))
            }
        })
    }
}

pub mod serde_boc {
    use super::*;

    pub fn serialize<S>(data: &SliceData, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_cell::serialize(&data.into_cell(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SliceData, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        serde_cell::deserialize(deserializer).map(From::from)
    }
}

pub mod serde_cell {
    use serde::de::Deserialize;
    use ton_types::Cell;

    pub fn serialize<S>(data: &Cell, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::Error;

        let bytes = ton_types::serialize_toc(data).map_err(S::Error::custom)?;
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Cell, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let data = String::deserialize(deserializer)?;
        let bytes = base64::decode(&data).map_err(D::Error::custom)?;
        let cell = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(&bytes))
            .map_err(D::Error::custom)?;
        Ok(cell)
    }
}

pub mod serde_message {
    use super::*;
    use serde::Deserialize;
    use ton_block::{Deserializable, Serializable};

    pub fn serialize<S>(data: &ton_block::Message, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;

        serde_cell::serialize(&data.serialize().map_err(S::Error::custom)?, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ton_block::Message, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let data = String::deserialize(deserializer)?;
        ton_block::Message::construct_from_base64(&data).map_err(D::Error::custom)
    }
}

pub mod serde_ton_block {
    use super::*;
    use serde::Deserialize;
    use ton_block::{Deserializable, Serializable};

    pub fn serialize<S, T>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: Serializable,
    {
        use serde::ser::Error;

        serde_cell::serialize(&data.serialize().map_err(S::Error::custom)?, serializer)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: Deserializable,
    {
        use serde::de::Error;

        let data = String::deserialize(deserializer)?;
        T::construct_from_base64(&data).map_err(D::Error::custom)
    }
}
