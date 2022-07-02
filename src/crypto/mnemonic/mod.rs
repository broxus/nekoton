use anyhow::Error;
use ed25519_dalek::Keypair;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Digest;

pub mod dict;
pub(super) mod labs;
pub(super) mod legacy;

const LANGUAGE: bip39::Language = bip39::Language::English;

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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedKey {
    pub words: Vec<&'static str>,
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
    use bip39::util::{Bits11, IterExt};

    let rng = &mut rand::thread_rng();

    pub fn generate_words(entropy: &[u8]) -> Vec<&'static str> {
        let wordlist = LANGUAGE.wordlist();

        let checksum_byte = sha2::Sha256::digest(entropy)[0];

        entropy
            .iter()
            .chain(Some(&checksum_byte))
            .bits()
            .map(|bits: Bits11| wordlist.get_word(bits))
            .collect()
    }

    GeneratedKey {
        account_type,
        words: match account_type {
            MnemonicType::Legacy => {
                let entropy: [u8; 32] = rng.gen();
                generate_words(&entropy)
            }
            MnemonicType::Labs(_) => {
                let entropy: [u8; 16] = rng.gen();
                generate_words(&entropy)
            }
        },
    }
}
