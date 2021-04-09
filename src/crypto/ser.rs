const NONCE_LENGTH: usize = 12;

pub mod hex_encode {

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

pub mod hex_pubkey {
    use ed25519_dalek::PublicKey;

    use super::hex_encode;

    pub fn serialize<S>(data: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&*hex::encode(&data.as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        hex_encode::deserialize(deserializer).and_then(|x| {
            PublicKey::from_bytes(x.as_slice()).map_err(|e| D::Error::custom(e.to_string()))
        })
    }
}

pub mod hex_nonce {
    use chacha20poly1305::Nonce;

    use super::*;

    pub fn serialize<S>(data: &Nonce, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        hex_encode::serialize(data, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Nonce, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        hex_encode::deserialize(deserializer).and_then(|x| {
            if x.len() != NONCE_LENGTH {
                Err(serde::de::Error::custom(format!(
                    "Bad nonce len: {}, expected: 12",
                    x.len()
                )))
            } else {
                Ok(Nonce::clone_from_slice(&*x))
            }
        })
    }
}
