use anyhow::Result;
use dyn_clone::DynClone;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ton_block::Serializable;
use zeroize::Zeroizing;

use nekoton_utils::*;

pub use mnemonic::{MnemonicType, NewMnemonicType};
pub use signer::Signer;

pub mod mnemonic;
pub mod password_cache;
pub mod signer;

pub trait UnsignedMessage: DynClone + Send + Sync {
    /// Adjust expiration timestamp from now
    fn refresh_timeout(&mut self, clock: &dyn Clock);

    /// Current expiration timestamp
    fn expire_at(&self) -> u32;

    /// Message body hash
    fn hash(&self) -> &[u8];

    /// Create signed message from prepared inputs
    /// # Arguments
    /// `signature` - signature, received from [`hash`]
    fn sign(&self, signature: &[u8; 64]) -> Result<SignedMessage>;
}

dyn_clone::clone_trait_object!(UnsignedMessage);

#[derive(Clone, Debug)]
pub struct SignedMessage {
    pub message: ton_block::Message,
    pub expire_at: u32,
}

impl Serialize for SignedMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::Error;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SignedMessageHelper {
            #[serde(with = "serde_uint256")]
            pub hash: ton_types::UInt256,
            pub expire_at: u32,
            #[serde(with = "serde_cell")]
            pub boc: ton_types::Cell,
        }

        let boc: ton_types::Cell = self
            .message
            .write_to_new_cell()
            .map_err(Error::custom)?
            .into();

        SignedMessageHelper {
            hash: boc.repr_hash(),
            expire_at: self.expire_at,
            boc,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SignedMessageHelper {
            pub expire_at: u32,
            #[serde(with = "serde_ton_block")]
            pub boc: ton_block::Message,
        }

        let SignedMessageHelper { expire_at, boc } =
            SignedMessageHelper::deserialize(deserializer)?;

        Ok(Self {
            message: boc,
            expire_at,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SharedSecret {
    pub source_public_key: ed25519_dalek::PublicKey,
    pub recipient_public_key: ed25519_dalek::PublicKey,
    pub secret: Zeroizing<[u8; 32]>,
}

impl SharedSecret {
    pub fn x25519(source: &ed25519_dalek::Keypair, target: &ed25519_dalek::PublicKey) -> Self {
        use curve25519_dalek_ng::scalar::Scalar;

        let extended = ed25519_dalek::ExpandedSecretKey::from(&source.secret);
        let mut k: [u8; 32] = extended.to_bytes()[0..32].try_into().unwrap();
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;

        let u = curve25519_dalek_ng::edwards::CompressedEdwardsY(target.to_bytes())
            .decompress()
            .unwrap() // shouldn't fail because bytes were extracted from public key
            .to_montgomery();

        let secret = Zeroizing::new((Scalar::from_bits(k) * u).to_bytes());

        Self {
            source_public_key: source.public,
            recipient_public_key: *target,
            secret,
        }
    }
}

define_string_enum!(
    #[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    pub enum EncryptionAlgorithm {
        ChaCha20Poly1305,
    }
);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedData {
    pub algorithm: EncryptionAlgorithm,
    #[serde(with = "serde_public_key")]
    pub source_public_key: ed25519_dalek::PublicKey,
    #[serde(with = "serde_public_key")]
    pub recipient_public_key: ed25519_dalek::PublicKey,
    #[serde(with = "serde_bytes_base64")]
    pub data: Vec<u8>,
    #[serde(with = "serde_bytes_base64")]
    pub nonce: Vec<u8>,
}
