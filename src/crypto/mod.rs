use anyhow::Result;
use async_trait::async_trait;
use downcast_rs::{impl_downcast, Downcast};
use dyn_clone::DynClone;
use ed25519_dalek::PublicKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ton_block::Serializable;
use zeroize::Zeroizing;

use nekoton_utils::*;

pub use derived_key::*;
pub use encrypted_key::*;
pub use ledger_key::*;
pub use mnemonic::*;
pub use password_cache::*;

mod derived_key;
mod encrypted_key;
mod ledger_key;
mod mnemonic;
mod password_cache;

pub type Signature = [u8; ed25519_dalek::SIGNATURE_LENGTH];
pub type PubKey = [u8; ed25519_dalek::PUBLIC_KEY_LENGTH];

pub trait UnsignedMessage: DynClone + Send + Sync {
    /// Adjust expiration timestamp from now
    fn refresh_timeout(&mut self, clock: &dyn Clock);

    /// Current expiration timestamp
    fn expire_at(&self) -> u32;

    /// Message body hash
    fn hash(&self) -> &[u8];

    /// Create signed message from prepared inputs
    /// # Arguments
    /// `signature` - signature, received from [`UnsignedMessage::hash`]
    fn sign(&self, signature: &Signature) -> Result<SignedMessage>;
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

        let cell: ton_types::Cell = self
            .message
            .write_to_new_cell()
            .map_err(Error::custom)?
            .into();

        SignedMessageHelper {
            hash: cell.repr_hash(),
            expire_at: self.expire_at,
            boc: cell,
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

#[async_trait]
pub trait Signer: SignerStorage {
    type CreateKeyInput: Serialize + DeserializeOwned;
    type ExportKeyInput: Serialize + DeserializeOwned;
    type ExportKeyOutput: Serialize + DeserializeOwned;
    type GetPublicKeys: Serialize + DeserializeOwned;
    type UpdateKeyInput: Serialize + DeserializeOwned;
    type SignInput: Serialize + DeserializeOwned;

    async fn add_key(
        &mut self,
        ctx: SignerContext<'_>,
        input: Self::CreateKeyInput,
    ) -> Result<SignerEntry>;

    async fn update_key(
        &mut self,
        ctx: SignerContext<'_>,
        input: Self::UpdateKeyInput,
    ) -> Result<SignerEntry>;

    async fn export_key(
        &self,
        ctx: SignerContext<'_>,
        input: Self::ExportKeyInput,
    ) -> Result<Self::ExportKeyOutput>;

    async fn get_public_keys(
        &self,
        ctx: SignerContext<'_>,
        input: Self::GetPublicKeys,
    ) -> Result<Vec<PublicKey>>;

    async fn compute_shared_secrets(
        &self,
        ctx: SignerContext<'_>,
        public_keys: &[PublicKey],
        input: Self::SignInput,
    ) -> Result<Vec<SharedSecret>>;

    async fn sign(
        &self,
        ctx: SignerContext<'_>,
        data: &[u8],
        input: Self::SignInput,
    ) -> Result<Signature>;
}

#[async_trait]
pub trait SignerStorage: Downcast + Send + Sync {
    fn load_state(&mut self, data: &str) -> Result<()>;
    fn store_state(&self) -> String;

    fn get_entries(&self) -> Vec<SignerEntry>;
    async fn remove_key(&mut self, public_key: &PublicKey) -> Option<SignerEntry>;
    async fn clear(&mut self);
}

impl_downcast!(SignerStorage);

#[derive(Copy, Clone)]
pub struct SignerContext<'a> {
    pub password_cache: &'a PasswordCache,
}

#[derive(Debug, Clone)]
pub struct SharedSecret {
    pub source_public_key: PublicKey,
    pub recipient_public_key: PublicKey,
    pub secret: Zeroizing<[u8; 32]>,
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
    pub source_public_key: PublicKey,
    #[serde(with = "serde_public_key")]
    pub recipient_public_key: PublicKey,
    #[serde(with = "serde_bytes_base64")]
    pub data: Vec<u8>,
    #[serde(with = "serde_bytes_base64")]
    pub nonce: Vec<u8>,
}

pub trait WithPublicKey {
    fn public_key(&self) -> &PublicKey;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerEntry {
    pub name: String,
    #[serde(with = "serde_public_key")]
    pub public_key: PublicKey,
    #[serde(with = "serde_public_key")]
    pub master_key: PublicKey,
    pub account_id: u16,
}

pub fn default_key_name(public_key: &PubKey) -> String {
    format!(
        "{}...{}",
        hex::encode(&public_key[0..2]),
        hex::encode(&public_key[30..32])
    )
}

pub mod x25519 {
    use curve25519_dalek_ng::scalar::Scalar;
    use zeroize::Zeroizing;

    pub fn compute_shared(
        k: &ed25519_dalek::SecretKey,
        u: &ed25519_dalek::PublicKey,
    ) -> Zeroizing<[u8; 32]> {
        let extended = ed25519_dalek::ExpandedSecretKey::from(k);
        let mut k: [u8; 32] = extended.to_bytes()[0..32].try_into().unwrap();
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;

        let u = curve25519_dalek_ng::edwards::CompressedEdwardsY(u.to_bytes())
            .decompress()
            .unwrap() // shouldn't fail because bytes were extracted from public key
            .to_montgomery();

        Zeroizing::new((Scalar::from_bits(k) * u).to_bytes())
    }
}
