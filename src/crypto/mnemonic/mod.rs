use anyhow::Error;
use ed25519_dalek::Keypair;
use rand::Rng;
use serde::de::{MapAccess, Unexpected, Visitor};
use serde::{de, Deserialize, Deserializer, Serialize};
use sha2::Digest;

pub mod dict;
pub(super) mod labs;
pub(super) mod legacy;

const LANGUAGE: bip39::Language = bip39::Language::English;

#[derive(Serialize, Copy, Clone, Debug, Eq, PartialEq)]
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

impl<'de> Deserialize<'de> for MnemonicType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MnemonicTypeVisitor;

        impl<'de> Visitor<'de> for MnemonicTypeVisitor {
            type Value = MnemonicType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("string 'Legacy' or object with 'Labs' or 'Bip39' key")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "Legacy" => Ok(MnemonicType::Legacy),
                    _ => Err(de::Error::invalid_value(Unexpected::Str(value), &"Legacy")),
                }
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                match map.next_key::<String>()? {
                    Some(key) => match key.as_str() {
                        "Labs" => {
                            let account_id = map.next_value()?;
                            Ok(MnemonicType::Bip39(Bip39MnemonicData {
                                account_id,
                                path: Bip39Path::Ever,
                                entropy: Bip39Entropy::Bits128,
                            }))
                        }
                        "Bip39" => {
                            let data: Bip39MnemonicData = map.next_value()?;
                            Ok(MnemonicType::Bip39(data))
                        }
                        _ => Err(de::Error::unknown_field(&key, &["Labs", "Bip39"])),
                    },
                    None => Err(de::Error::missing_field("type")),
                }
            }
        }

        deserializer.deserialize_any(MnemonicTypeVisitor)
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub struct Bip39MnemonicData {
    pub account_id: u16,
    pub path: Bip39Path,
    pub entropy: Bip39Entropy,
}

impl Bip39MnemonicData {
    pub fn labs_old(account_id: u16) -> Self {
        Self {
            account_id,
            path: Bip39Path::Ever,
            entropy: Bip39Entropy::Bits128,
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Bip39Path {
    Ever,
    Ton,
}

impl Bip39Path {
    pub const fn derivation_path(self) -> &'static str {
        match self {
            Self::Ton => "m/44'/607'/0'",
            Self::Ever => "m/44'/396'/0'",
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Bip39Entropy {
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

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::crypto::{Bip39Entropy, Bip39MnemonicData, Bip39Path, MnemonicType};

    #[test]
    fn mnemonic_type_deserialize() {
        #[derive(Deserialize)]
        struct Test {
            mnemonic_type: MnemonicType,
        }

        let legacy = r#"{"mnemonic_type":"Legacy"}"#;
        let legacy_mnemonic: Test = serde_json::from_str(legacy).unwrap();
        assert_eq!(legacy_mnemonic.mnemonic_type, MnemonicType::Legacy);

        let labs = r#"{"mnemonic_type":{"Labs":2}}"#;
        let labs_mnemonic: Test = serde_json::from_str(labs).unwrap();
        assert_eq!(
            labs_mnemonic.mnemonic_type,
            MnemonicType::Bip39(Bip39MnemonicData::labs_old(2))
        );

        let bip39 =
            r#"{"mnemonic_type":{"Bip39":{"account_id":0,"path":"ever","entropy":"bits128"}}}"#;
        let bip39_mnemonic: Test = serde_json::from_str(bip39).unwrap();
        assert_eq!(
            bip39_mnemonic.mnemonic_type,
            MnemonicType::Bip39(Bip39MnemonicData {
                account_id: 0,
                path: Bip39Path::Ever,
                entropy: Bip39Entropy::Bits128,
            })
        );
    }
}
