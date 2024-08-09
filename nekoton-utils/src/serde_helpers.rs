use std::borrow::Cow;
use std::convert::TryInto;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};
use ton_block::MsgAddressInt;
use ton_types::{Cell, SliceData, UInt256};

struct StringOrNumber(u64);

impl Serialize for StringOrNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0 <= 0x1fffffffffffffu64 || !serializer.is_human_readable() {
            serializer.serialize_u64(self.0)
        } else {
            serializer.serialize_str(&self.0.to_string())
        }
    }
}

impl<'de> Deserialize<'de> for StringOrNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Value<'a> {
            String(#[serde(borrow)] Cow<'a, str>),
            Number(u64),
        }

        match Value::deserialize(deserializer)? {
            Value::String(str) => u64::from_str(str.as_ref())
                .map(Self)
                .map_err(|_| D::Error::custom("Invalid number")),
            Value::Number(value) => Ok(Self(value)),
        }
    }
}

pub mod serde_u64 {
    use super::*;

    pub fn serialize<S>(data: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        StringOrNumber(*data).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StringOrNumber::deserialize(deserializer).map(|StringOrNumber(x)| x)
    }
}

pub mod serde_optional_u64 {
    use super::*;

    pub fn serialize<S>(data: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        data.map(StringOrNumber).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Option::<StringOrNumber>::deserialize(deserializer)?.map(|StringOrNumber(x)| x))
    }
}

pub mod serde_duration_sec {
    use super::*;

    pub fn serialize<S>(data: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        StringOrNumber(data.as_secs()).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StringOrNumber::deserialize(deserializer).map(|StringOrNumber(x)| Duration::from_secs(x))
    }
}

pub mod serde_duration_ms {
    use super::*;

    pub fn serialize<S>(data: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        StringOrNumber(data.as_millis() as u64).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StringOrNumber::deserialize(deserializer).map(|StringOrNumber(x)| Duration::from_millis(x))
    }
}

pub mod serde_base64_array {
    use super::*;

    pub fn serialize<S>(data: &dyn AsRef<[u8]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes_base64::serialize(data, serializer)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = serde_bytes_base64::deserialize(deserializer)?;
        data.try_into()
            .map_err(|_| D::Error::custom(format!("Invalid array length, expected: {N}")))
    }
}

pub mod serde_hex_array {
    use super::*;

    pub fn serialize<S>(data: &dyn AsRef<[u8]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_bytes::serialize(data, serializer)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = serde_bytes::deserialize(deserializer)?;
        data.try_into()
            .map_err(|_| D::Error::custom(format!("Invalid array length, expected: {N}")))
    }
}

pub mod serde_optional_hex_array {
    use super::*;

    pub fn serialize<S, T>(data: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]> + Sized,
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Wrapper<'a>(#[serde(with = "serde_bytes")] &'a [u8]);

        match data {
            Some(data) => serializer.serialize_some(&Wrapper(data.as_ref())),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<Option<[u8; N]>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(with = "serde_bytes")] Vec<u8>);

        let data = Option::<Wrapper>::deserialize(deserializer)?;
        Ok(match data {
            Some(data) => Some(
                data.0
                    .try_into()
                    .map_err(|_| Error::custom(format!("Invalid array length, expected: {N}")))?,
            ),
            None => None,
        })
    }
}

pub mod serde_string {
    use super::*;

    pub fn serialize<S>(data: &dyn fmt::Display, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        data.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        String::deserialize(deserializer)
            .and_then(|data| T::from_str(&data).map_err(D::Error::custom))
    }
}

pub mod serde_optional_string {
    use super::*;

    pub fn serialize<S, T>(data: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: fmt::Display,
    {
        data.as_ref().map(ToString::to_string).serialize(serializer)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: FromStr,
        T::Err: fmt::Display,
    {
        Option::<String>::deserialize(deserializer).and_then(|data| {
            data.map(|data| T::from_str(&data).map_err(Error::custom))
                .transpose()
        })
    }
}

pub mod serde_string_array {
    use super::*;

    pub fn serialize<S, T>(data: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: fmt::Display,
    {
        data.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
            .serialize(serializer)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        T: Deserialize<'de> + FromStr,
        D: serde::Deserializer<'de>,
        <T as FromStr>::Err: fmt::Display,
    {
        let s = String::deserialize(deserializer)?;
        if s.contains(',') {
            let mut v = Vec::new();
            for url in s.split(',') {
                v.push(T::from_str(url).map_err(Error::custom)?);
            }
            Ok(v)
        } else {
            Ok(vec![T::from_str(&s).map_err(Error::custom)?])
        }
    }
}

pub mod serde_uint256 {
    use super::*;

    pub fn serialize<S>(data: &UInt256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_hex_array::serialize(data.as_slice(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<UInt256, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: [u8; 32] = serde_hex_array::deserialize(deserializer)?;
        Ok(UInt256::from_slice(&data[..]))
    }
}

pub mod serde_optional_uint256 {
    use super::*;

    pub fn serialize<S>(data: &Option<UInt256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_optional_hex_array::serialize(&data.as_ref(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<UInt256>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: Option<[u8; 32]> = serde_optional_hex_array::deserialize(deserializer)?;
        Ok(data.map(|data| UInt256::from_slice(&data[..])))
    }
}

pub mod serde_vec_uint256 {
    use super::*;

    pub fn serialize<S>(data: &[UInt256], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(data.len()))?;
        for item in data {
            seq.serialize_element(&item.to_hex_string())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<UInt256>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct VecVisitor;
        impl<'de> Visitor<'de> for VecVisitor {
            type Value = Vec<UInt256>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("vector of UInt256")
            }
            fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(elem) = visitor.next_element::<String>()? {
                    let item = UInt256::from_str(&elem)
                        .map_err(|_| V::Error::custom("Invalid uint256"))?;
                    vec.push(item);
                }
                Ok(vec)
            }
        }

        deserializer.deserialize_seq(VecVisitor)
    }
}

pub mod serde_optional_vec_uint256 {
    use super::*;

    pub fn serialize<S>(data: &Option<Vec<UInt256>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Wrapper<'a>(#[serde(with = "serde_vec_uint256")] &'a [UInt256]);
        match data {
            Some(data) => serializer.serialize_some(&Wrapper(data)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<UInt256>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(with = "serde_vec_uint256")] Vec<UInt256>);
        Ok(Option::<_>::deserialize(deserializer)?.map(|Wrapper(data)| data))
    }
}

pub mod serde_address {
    use super::*;

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

    pub fn serialize<S>(data: &Option<MsgAddressInt>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde::Serialize)]
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
        #[derive(serde::Deserialize)]
        #[serde(transparent)]
        struct Wrapper(#[serde(with = "serde_address")] MsgAddressInt);

        Option::<Wrapper>::deserialize(deserializer).map(|wrapper| wrapper.map(|data| data.0))
    }
}

pub mod serde_vec_address {
    use super::*;

    pub fn serialize<S>(data: &[MsgAddressInt], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(data.len()))?;
        for address in data {
            seq.serialize_element(&address.to_string())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<MsgAddressInt>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct VecVisitor;

        impl<'de> Visitor<'de> for VecVisitor {
            type Value = Vec<MsgAddressInt>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("vector of addresses")
            }

            fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(elem) = visitor.next_element::<String>()? {
                    let item = MsgAddressInt::from_str(&elem)
                        .map_err(|_| V::Error::custom("Invalid address"))?;
                    vec.push(item);
                }
                Ok(vec)
            }
        }

        deserializer.deserialize_seq(VecVisitor)
    }
}

pub mod serde_bytes {
    use std::fmt;

    use serde::de::Unexpected;

    use super::*;

    pub fn serialize<S>(data: &dyn AsRef<[u8]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(data.as_ref()))
        } else {
            serializer.serialize_bytes(data.as_ref())
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct HexVisitor;

        impl<'de> Visitor<'de> for HexVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("hex-encoded byte array")
            }

            fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
                hex::decode(value).map_err(|_| E::invalid_type(Unexpected::Str(value), &self))
            }

            // See the `deserializing_flattened_field` test for an example why this is needed.
            fn visit_bytes<E: Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(value.to_vec())
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(HexVisitor)
        } else {
            deserializer.deserialize_bytes(BytesVisitor)
        }
    }
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("byte array")
    }

    fn visit_bytes<E: Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(value.to_vec())
    }
}

pub mod serde_bytes_base64 {
    use serde::de::Unexpected;

    use super::*;

    pub fn serialize<S>(data: &dyn AsRef<[u8]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(base64::encode(data.as_ref()).as_str())
        } else {
            serializer.serialize_bytes(data.as_ref())
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Base64Visitor;

        impl<'de> Visitor<'de> for Base64Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("base64-encoded byte array")
            }

            fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
                base64::decode(value).map_err(|_| E::invalid_type(Unexpected::Str(value), &self))
            }

            // See the `deserializing_flattened_field` test for an example why this is needed.
            fn visit_bytes<E: Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                Ok(value.to_vec())
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(Base64Visitor)
        } else {
            deserializer.deserialize_bytes(BytesVisitor)
        }
    }
}

pub mod serde_bytes_base64_optional {
    use super::*;

    pub fn serialize<S, T>(data: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: AsRef<[u8]>,
    {
        #[derive(serde::Serialize)]
        #[serde(transparent)]
        struct Wrapper<'a>(#[serde(with = "serde_bytes_base64")] &'a [u8]);

        match data {
            Some(data) => serializer.serialize_some(&Wrapper(data.as_ref())),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(transparent)]
        struct Wrapper(#[serde(with = "serde_bytes_base64")] Vec<u8>);

        Option::<Wrapper>::deserialize(deserializer).map(|wrapper| wrapper.map(|data| data.0))
    }
}

pub mod serde_iter {
    pub fn serialize<S, T, V>(iter: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
        T: IntoIterator<Item = V> + Clone,
        V: serde::Serialize,
    {
        use serde::ser::SerializeSeq;

        let iter = iter.clone().into_iter();
        let mut seq = serializer.serialize_seq(Some(iter.size_hint().0))?;
        for value in iter {
            seq.serialize_element(&value)?;
        }
        seq.end()
    }
}

pub mod serde_boc {
    use super::*;

    pub fn serialize<S>(data: &SliceData, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_cell::serialize(&data.clone().into_cell(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SliceData, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cell = serde_cell::deserialize(deserializer)?;
        SliceData::load_cell(cell).map_err(D::Error::custom)
    }
}

pub mod serde_cell {
    use super::*;

    pub fn serialize<S>(data: &Cell, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::Error;

        let bytes = ton_types::serialize_toc(data).map_err(Error::custom)?;
        serde_bytes_base64::serialize(&bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Cell, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = serde_bytes_base64::deserialize(deserializer)?;
        let cell =
            ton_types::deserialize_tree_of_cells(&mut bytes.as_slice()).map_err(Error::custom)?;
        Ok(cell)
    }
}

pub mod serde_ton_block {
    use ton_block::{Deserializable, Serializable};

    use super::*;

    pub fn serialize<S>(data: &dyn Serializable, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;

        serde_cell::serialize(&data.serialize().map_err(Error::custom)?, serializer)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: Deserializable,
    {
        let data = String::deserialize(deserializer)?;
        T::construct_from_base64(&data).map_err(Error::custom)
    }
}

pub mod serde_account_stuff {
    use super::*;

    #[inline(always)]
    pub fn serialize<S>(data: &ton_block::AccountStuff, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_ton_block::serialize(data, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ton_block::AccountStuff, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?;
        let bytes = base64::decode(data).map_err(D::Error::custom)?;
        ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())
            .and_then(crate::deserialize_account_stuff)
            .map_err(D::Error::custom)
    }
}

pub mod serde_secret_key {
    use super::*;

    pub fn serialize<S>(data: &ed25519_dalek::SecretKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(data.as_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ed25519_dalek::SecretKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?;
        let bytes = hex::decode(data).map_err(|_| D::Error::custom("Invalid SecretKey"))?;
        ed25519_dalek::SecretKey::from_bytes(&bytes)
            .map_err(|_| D::Error::custom("Invalid SecretKey"))
    }
}

pub mod serde_public_key {
    use super::*;

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
        let bytes = hex::decode(data).map_err(|_| Error::custom("Invalid PublicKey"))?;
        ed25519_dalek::PublicKey::from_bytes(&bytes).map_err(|_| Error::custom("Invalid PublicKey"))
    }
}

pub mod serde_vec_public_key {
    use super::*;

    pub fn serialize<S>(data: &[ed25519_dalek::PublicKey], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(data.len()))?;
        for pubkey in data {
            seq.serialize_element(&hex::encode(pubkey.as_bytes()))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<ed25519_dalek::PublicKey>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct VecVisitor;
        impl<'de> Visitor<'de> for VecVisitor {
            type Value = Vec<ed25519_dalek::PublicKey>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("vector of public keys")
            }
            fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(elem) = visitor.next_element::<String>()? {
                    let bytes =
                        hex::decode(elem).map_err(|_| V::Error::custom("Invalid PublicKey"))?;
                    let pubkey = ed25519_dalek::PublicKey::from_bytes(&bytes)
                        .map_err(|_| Error::custom("Invalid PublicKey"))?;
                    vec.push(pubkey);
                }
                Ok(vec)
            }
        }

        deserializer.deserialize_seq(VecVisitor)
    }
}

#[cfg(feature = "encryption")]
pub mod serde_nonce {
    use chacha20poly1305::Nonce;

    use crate::encryption::NONCE_LENGTH;

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
                    "Bad nonce len: {}, expected: {}",
                    x.len(),
                    NONCE_LENGTH
                )))
            } else {
                Ok(Nonce::clone_from_slice(&x))
            }
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_hex() {
        #[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
        struct Test {
            #[serde(with = "serde_hex_array")]
            key: [u8; 32],
        }
        let test = Test { key: [1; 32] };
        let data = serde_json::to_string(&test).unwrap();
        assert_eq!(
            data,
            r#"{"key":"0101010101010101010101010101010101010101010101010101010101010101"}"#
        );
        assert_eq!(serde_json::from_str::<Test>(&data).unwrap(), test);
        let data = bincode::serialize(&test).unwrap();
        assert!(data.len() < 64);
        assert_eq!(bincode::deserialize::<Test>(&data).unwrap(), test);
    }

    #[test]
    fn test_optional() {
        #[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
        struct Test {
            #[serde(with = "serde_bytes_base64_optional")]
            key: Option<Vec<u8>>,
        }

        let data = Test {
            key: Some(vec![1; 32]),
        };
        let res = serde_json::to_string(&data).unwrap();
        assert_eq!(
            r#"{"key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}"#,
            res
        );
        assert_eq!(data, serde_json::from_str(&res).unwrap());

        let data = Test { key: None };
        let res = serde_json::to_string(&data).unwrap();
        assert_eq!(r#"{"key":null}"#, res);
        assert_eq!(data, serde_json::from_str(&res).unwrap())
    }

    #[test]
    fn test_optional_hex_array() {
        #[derive(Serialize, Deserialize)]
        struct Test {
            #[serde(with = "serde_optional_hex_array")]
            field: Option<[u8; 32]>,
        }

        let target: [u8; 32] =
            hex::decode("0101010101010101010101010101010101010101010101010101010101010101")
                .unwrap()
                .try_into()
                .unwrap();

        let serialized = serde_json::to_string(&Test {
            field: Some(target),
        })
        .unwrap();
        let deserialized: Test = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.field, Some(target));

        let serialized = serde_json::to_string(&Test { field: None }).unwrap();
        let deserialized: Test = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.field, None);
    }
}
