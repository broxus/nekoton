use anyhow::Result;
use async_trait::async_trait;
use downcast_rs::{impl_downcast, Downcast};
use dyn_clone::DynClone;
use ed25519_dalek::PublicKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

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

pub trait UnsignedMessage: DynClone + Send {
    /// Adjust expiration timestamp from now
    fn refresh_timeout(&mut self, clock: &dyn Clock);

    /// Current expiration timestamp
    fn expire_at(&self) -> u32;

    /// Message body hash
    fn hash(&self) -> &[u8];

    /// Create signed message from prepared inputs
    /// # Arguments
    /// `signature` - signature, received from [`hash`]
    fn sign(&self, signature: &Signature) -> Result<SignedMessage>;
}

dyn_clone::clone_trait_object!(UnsignedMessage);

#[derive(Clone, Debug)]
pub struct SignedMessage {
    pub message: ton_block::Message,
    pub expire_at: u32,
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

pub trait WithPublicKey {
    fn public_key(&self) -> &PublicKey;
}

#[derive(Clone, Serialize, Deserialize, Debug)]
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
