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
    /// Phrase with 12 or 24 words, used everywhere else. The additional parameter is used in
    /// derivation path to create multiple keys from one mnemonic
    Bip39(Bip39MnemonicData),
}

impl MnemonicType {
    pub fn account_id(self) -> u16 {
        match self {
            Self::Legacy => 0,
            Self::Bip39(item) => item.account_id,
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct Bip39MnemonicData {
    pub account_id: u16,
    pub network: Bip39Type,
    pub entropy: Bip39Entropy,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub enum Bip39Type {
    #[default]
    Ever,
    Ton,
}

impl Bip39Type {
    pub const fn derivation_path(self) -> &'static str {
        match self {
            Self::Ton => "m/44'/607'/0'",
            Self::Ever => "m/44'/396'/0'",
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub enum Bip39Entropy {
    #[default]
    Bits128,
    Bits256,
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
        MnemonicType::Bip39(data) => labs::derive_from_phrase(phrase, data),
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

    let entropy_size = match account_type {
        MnemonicType::Legacy => 32,
        MnemonicType::Bip39(data) => match data.entropy {
            Bip39Entropy::Bits128 => 16,
            Bip39Entropy::Bits256 => 32,
        },
    };

    let entropy = (0..entropy_size)
        .map(|_| rng.gen::<u8>())
        .collect::<Vec<u8>>();

    GeneratedKey {
        account_type,
        words: generate_words(&entropy),
    }
}
