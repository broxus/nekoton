pub use nekoton_utils::*;

#[cfg(feature = "wallet")]
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

#[cfg(feature = "wallet")]
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

#[cfg(feature = "wallet")]
pub mod serde_vec_public_key {
    use serde::de::Error;
    use serde::de::SeqAccess;
    use serde::de::Visitor;
    use serde::ser::SerializeSeq;

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
