use anyhow::Result;
use ed25519_dalek::Keypair;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use zeroize::Zeroize;

pub mod bip39;
pub mod dict;
pub mod legacy;

const LANGUAGE: ::bip39::Language = ::bip39::Language::English;

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum MnemonicType {
    /// Phrase with 24 words, used in Crystal Wallet
    Legacy,
    /// Phrase with 12-24 words, used everywhere else
    Bip39,
}

pub fn derive_from_phrase(
    phrase: &str,
    mnemonic_type: MnemonicType,
    account_id: u16,
) -> Result<Keypair> {
    match mnemonic_type {
        MnemonicType::Legacy if account_id == 0 => legacy::derive_from_phrase(phrase),
        MnemonicType::Legacy => Err(MnemonicError::UnsupportedAccountId.into()),
        MnemonicType::Bip39 => {
            bip39::derive_from_phrase(phrase, &bip39::make_default_path(account_id))
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum NewMnemonicType {
    /// Phrase with 24 words, used in Crystal Wallet
    Legacy,
    /// Phrase with 12-24 words, used everywhere else
    Bip39(bip39::MnemonicType),
}

/// Generates mnemonic and keypair.
pub fn generate_phrase(mnemonic_type: NewMnemonicType) -> Vec<&'static str> {
    use ::bip39::util::{Bits11, IterExt};

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

    let mut entropy = [0u8; 32];
    let words = match mnemonic_type {
        NewMnemonicType::Legacy => {
            rng.fill_bytes(&mut entropy);
            generate_words(&entropy)
        }
        NewMnemonicType::Bip39(mnemonic_type) => {
            let entropy = &mut entropy[..mnemonic_type.entropy_bits() / 8];
            rng.fill_bytes(entropy);
            generate_words(entropy)
        }
    };
    entropy.zeroize();

    words
}

#[derive(thiserror::Error, Debug)]
enum MnemonicError {
    #[error("Unsupported account id")]
    UnsupportedAccountId,
}
