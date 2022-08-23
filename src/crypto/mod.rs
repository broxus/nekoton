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
