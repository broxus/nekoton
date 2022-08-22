use anyhow::Result;
use async_trait::async_trait;
use downcast_rs::{impl_downcast, Downcast};
use ed25519_dalek::PublicKey;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use nekoton_utils::*;

use crate::crypto::password_cache::PasswordCache;
use crate::crypto::SharedSecret;

pub use derived::DerivedSigner;
pub use ledger::LedgerSigner;
pub use simple::SimpleSigner;

pub mod derived;
pub mod ledger;
pub mod simple;

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
    ) -> Result<[u8; 64]>;
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

pub fn default_key_name(public_key: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]) -> String {
    format!(
        "{}...{}",
        hex::encode(&public_key[0..2]),
        hex::encode(&public_key[30..32])
    )
}
