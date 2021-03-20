use anyhow::Error;
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};

mod labs;
mod legacy;
mod util;

use crate::storage::keystore::KeystoreError;

#[derive(Serialize, Deserialize, Copy, Clone)]
pub enum AccountType {
    Legacy,
    Labs(u16),
}

pub struct GeneratedKey {
    pub words: Vec<String>,
    pub account_type: AccountType,
}

/// Derives keypair from wordlist.
/// 24 words for  [`LEGACY_MNEMONIC`] or 12 for [`LABS_MNEMONIC`]
/// # Arguments
/// * `phrase` 12 or 24 words
///  * `mnemonic_type` -  [`LEGACY_MNEMONIC`] or [`LABS_MNEMONIC`]
pub fn derive_from_words(mnemonic: &str, account_type: AccountType) -> Result<Keypair, Error> {
    match account_type {
        AccountType::Legacy => legacy::derive_from_words(&mnemonic),
        AccountType::Labs(id) => labs::derive_from_words(&mnemonic, id),
    }
}

/// Generates mnemonic and keypair.
pub fn generate(account_type: AccountType) -> Result<GeneratedKey, Error> {
    use ring::rand;
    use ring::rand::SecureRandom;

    let rng = rand::SystemRandom::new();

    let mut entropy = [0; 256 / 8];
    rng.fill(&mut entropy)
        .map_err(KeystoreError::FailedToGenerateRandomBytes)?;
    match account_type {
        AccountType::Legacy => Ok(legacy::generate_words(entropy)),
        AccountType::Labs(_) => labs::generate_words(entropy),
    }
    .map(|words| GeneratedKey {
        account_type,
        words,
    })
}
