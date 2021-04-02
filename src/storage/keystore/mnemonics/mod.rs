use anyhow::Error;
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};

mod labs;
mod legacy;
mod util;

use crate::storage::keystore::KeyStoreError;

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
    Ok(GeneratedKey {
        account_type,
        words: match account_type {
            AccountType::Legacy => legacy::generate_words(generate_entropy::<32>()?),
            AccountType::Labs(_) => labs::generate_words(generate_entropy::<16>()?),
        },
    })
}

fn generate_entropy<const N: usize>() -> Result<[u8; N], KeyStoreError> {
    use ring::rand::SecureRandom;

    let rng = ring::rand::SystemRandom::new();

    let mut entropy = [0; N];
    rng.fill(&mut entropy)
        .map_err(KeyStoreError::FailedToGenerateRandomBytes)?;
    Ok(entropy)
}
