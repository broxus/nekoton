use anyhow::Error;
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};

mod hints;
mod labs;
mod legacy;
mod util;
pub use hints::get_hints;
pub(super) use labs::derive_master_key;
#[derive(Serialize, Deserialize, Copy, Clone)]
pub enum MnemonicType {
    /// Phrase with 24 words, used in Crystal Wallet
    Legacy,
    /// Phrase with 12 words, used everywhere else. The additional parameter is used in
    /// derivation path to create multiple keys from one mnemonic
    Labs(u16),
}

pub struct GeneratedKey {
    pub words: Vec<String>,
    pub account_type: MnemonicType,
}

pub fn derive_from_phrase(phrase: &str, mnemonic_type: MnemonicType) -> Result<Keypair, Error> {
    match mnemonic_type {
        MnemonicType::Legacy => legacy::derive_from_phrase(phrase),
        MnemonicType::Labs(account_id) => labs::derive_from_phrase(phrase, account_id),
    }
}

/// Generates mnemonic and keypair.
pub fn generate_key(account_type: MnemonicType) -> Result<GeneratedKey, Error> {
    Ok(GeneratedKey {
        account_type,
        words: match account_type {
            MnemonicType::Legacy => legacy::generate_words(generate_entropy::<32>()?),
            MnemonicType::Labs(_) => labs::generate_words(generate_entropy::<16>()?),
        },
    })
}

fn generate_entropy<const N: usize>() -> Result<[u8; N], MnemonicError> {
    use ring::rand::SecureRandom;

    let rng = ring::rand::SystemRandom::new();

    let mut entropy = [0; N];
    rng.fill(&mut entropy)
        .map_err(MnemonicError::FailedToGenerateRandomBytes)?;
    Ok(entropy)
}

#[derive(thiserror::Error, Debug)]
enum MnemonicError {
    #[error("Failed to generate random bytes")]
    FailedToGenerateRandomBytes(ring::error::Unspecified),
}
