mod derived_key;
mod encrypted_key;
mod mnemonic;
pub(crate) mod ser;
mod symmetric;

pub use encrypted_key::EncryptedKey;
pub use mnemonic::*;

use anyhow::Result;
use dyn_clone::DynClone;

pub trait UnsignedMessage: DynClone {
    fn hash(&self) -> &[u8];
    fn sign(&self, signature: &[u8; ed25519_dalek::SIGNATURE_LENGTH]) -> Result<SignedMessage>;
}

dyn_clone::clone_trait_object!(UnsignedMessage);

#[derive(Clone)]
pub struct SignedMessage {
    pub message: ton_block::Message,
    pub expire_at: u32,
}
