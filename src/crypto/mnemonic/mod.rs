use anyhow::Error;
use ed25519_dalek::Keypair;
use rand::Rng;
use serde::{Deserialize, Serialize};

pub mod dict;
pub(super) mod labs;
pub(super) mod legacy;
mod utils;

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum MnemonicType {
    /// Phrase with 24 words, used in Crystal Wallet
    Legacy,
    /// Phrase with 12 words, used everywhere else. The additional parameter is used in
    /// derivation path to create multiple keys from one mnemonic
    Labs(u16),
}

impl MnemonicType {
    pub fn account_id(self) -> u16 {
        match self {
            Self::Legacy => 0,
            Self::Labs(id) => id,
        }
    }
}

#[derive(Debug)]
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
pub fn generate_key(account_type: MnemonicType) -> GeneratedKey {
    let rng = &mut rand::thread_rng();

    GeneratedKey {
        account_type,
        words: match account_type {
            MnemonicType::Legacy => legacy::generate_words(rng.gen()),
            MnemonicType::Labs(_) => labs::generate_words(rng.gen()),
        },
    }
}
