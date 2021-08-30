use std::convert::TryInto;
use std::str::FromStr;

use num_bigint::BigUint;
use serde::de::{Deserialize, Error, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeSeq};
use ton_block::MsgAddressInt;
use ton_types::{Cell, SliceData, UInt256};

pub mod serde_base64_array {
    use super::*;

    pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]> + Sized,
        S: serde::Serializer,
    {
        serializer.serialize_str(&base64::encode(&data.as_ref()))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?;
        let data = base64::decode(data).map_err(D::Error::custom)?;
        data.try_into()
            .map_err(|_| D::Error::custom(format!("Invalid array length, expected: {}", N)))
    }
}

pub mod serde_hex_array {
    use super::*;

    pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]> + Sized,
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(&data.as_ref()))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?;
        let data = hex::decode(data).map_err(D::Error::custom)?;
        data.try_into()
            .map_err(|_| D::Error::custom(format!("Invalid array length, expected: {}", N)))
    }
}

pub mod serde_u64 {
    use super::*;

    pub fn serialize<S>(data: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        data.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|data| u64::from_str(&data).map_err(D::Error::custom))
    }
}

pub mod serde_uint256 {
    use super::*;

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

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    use super::*;

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
        String::deserialize(deserializer)
            .and_then(|string| hex::decode(string).map_err(|e| D::Error::custom(e.to_string())))
    }
}

pub mod serde_bytes_base64 {
    use super::*;

    pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]> + Sized,
        S: serde::Serializer,
    {
        serializer.serialize_str(&*base64::encode(&data.as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|string| base64::decode(string).map_err(|e| D::Error::custom(e.to_string())))
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
    use super::*;

    pub fn serialize<S>(data: &Cell, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::Error;

        let bytes = ton_types::serialize_toc(data).map_err(S::Error::custom)?;
        serializer.serialize_str(&base64::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Cell, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?;
        let bytes = base64::decode(&data).map_err(D::Error::custom)?;
        let cell = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(&bytes))
            .map_err(D::Error::custom)?;
        Ok(cell)
    }
}

pub mod serde_message {
    use super::*;
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
        let data = String::deserialize(deserializer)?;
        ton_block::Message::construct_from_base64(&data).map_err(D::Error::custom)
    }
}

pub mod serde_ton_block {
    use super::*;
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
        let data = String::deserialize(deserializer)?;
        T::construct_from_base64(&data).map_err(D::Error::custom)
    }
}

pub mod serde_biguint {
    use super::*;

    pub fn serialize<S>(data: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&data.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?;
        BigUint::from_str(&data).map_err(|_| D::Error::custom("Invalid uint256"))
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
        let bytes = hex::decode(&data).map_err(|_| D::Error::custom("Invalid SecretKey"))?;
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
        let bytes = hex::decode(&data).map_err(|_| D::Error::custom("Invalid PublicKey"))?;
        ed25519_dalek::PublicKey::from_bytes(&bytes)
            .map_err(|_| D::Error::custom("Invalid PublicKey"))
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
                        hex::decode(&elem).map_err(|_| V::Error::custom("Invalid PublicKey"))?;
                    let pubkey = ed25519_dalek::PublicKey::from_bytes(&bytes)
                        .map_err(|_| V::Error::custom("Invalid PublicKey"))?;
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

    use super::*;
    use crate::encryption::NONCE_LENGTH;

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
