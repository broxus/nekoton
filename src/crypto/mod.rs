mod derived_key;
mod encrypted_key;
mod mnemonic;
mod symmetric;

pub use derived_key::*;
pub use encrypted_key::*;
pub use mnemonic::*;

use anyhow::Result;
use dyn_clone::DynClone;

pub trait UnsignedMessage: DynClone {
    /// Adjust expiration timestamp from now
    fn refresh_timeout(&mut self);

    /// Current expiration timestamp
    fn expire_at(&self) -> u32;

    /// Message body hash
    fn hash(&self) -> &[u8];

    /// Create signed message from prepared inputs
    /// # Arguments
    /// `signature` - signature, received from [`hash`]
    fn sign(&self, signature: &[u8; ed25519_dalek::SIGNATURE_LENGTH]) -> Result<SignedMessage>;
}

dyn_clone::clone_trait_object!(UnsignedMessage);

#[derive(Clone)]
pub struct SignedMessage {
    pub message: ton_block::Message,
    pub expire_at: u32,
}
