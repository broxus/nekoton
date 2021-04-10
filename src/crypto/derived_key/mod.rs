use std::collections::HashMap;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

use crate::storage::{Signer as StoreSigner, SignerEntry, SignerStorage};
use anyhow::Result;
use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{PublicKey, Signer};
use ring::digest;
use ring::rand::SecureRandom;
use secstr::{SecStr, SecVec};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::symmetric::symmetric_key_from_password;
use crate::crypto::{derive_from_phrase, derive_master_key, MnemonicType};
use crate::utils::*;

#[derive(Default, Clone, Debug)]
pub struct DerivedKeySigner {
    master_key: Option<MasterKey>,
}

impl DerivedKeySigner {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl StoreSigner for DerivedKeySigner {
    type CreateKeyInput = DerivedKeyCreateInput;
    type ExportKeyInput = DerivedKeyExportParams;
    type ExportKeyOutput = DerivedKeyExportOutput;
    type SignInput = DerivedKeySignParams;

    async fn add_key(&mut self, name: &str, input: Self::CreateKeyInput) -> Result<PublicKey> {
        let public = match input {
            DerivedKeyCreateInput::Import { phrase, password } => {
                let master_key = MasterKey::new(password, phrase, name.to_string())?;
                let public_key = master_key.public_key;
                self.master_key = Some(master_key);
                public_key
            }
            DerivedKeyCreateInput::Derive {
                account_id,
                password,
            } => {
                let master_key = match &mut self.master_key {
                    Some(key) => key,
                    None => return Err(MasterKeyError::MasterKeyNotFound.into()),
                };

                let decrypter = ChaCha20Poly1305::new(
                    &super::symmetric::symmetric_key_from_password(password, &master_key.salt),
                );

                let master = decrypt_secure(
                    &decrypter,
                    &master_key.entropy_nonce,
                    &*master_key.enc_entropy,
                )?;

                let public_key = derive_from_master(account_id, master)?.public;
                master_key
                    .accounts_map
                    .insert(public_key.to_bytes(), (name.to_owned(), account_id));

                public_key
            }
        };
        Ok(public)
    }

    async fn export_key(&self, input: Self::ExportKeyInput) -> Result<Self::ExportKeyOutput> {
        let master_key = match &self.master_key {
            Some(key) => key,
            None => return Err(MasterKeyError::MasterKeyNotFound.into()),
        };

        let decrypter = ChaCha20Poly1305::new(&super::symmetric::symmetric_key_from_password(
            input.password,
            &master_key.salt,
        ));

        let phrase = decrypt_secure(
            &decrypter,
            &master_key.phrase_nonce,
            &*master_key.enc_phrase,
        )?;

        Ok(Self::ExportKeyOutput { phrase })
    }

    async fn sign(&self, data: &[u8], input: Self::SignInput) -> Result<[u8; 64]> {
        let master_key = match &self.master_key {
            Some(key) => key,
            None => return Err(MasterKeyError::MasterKeyNotFound.into()),
        };

        let decrypter = ChaCha20Poly1305::new(&super::symmetric::symmetric_key_from_password(
            input.password,
            &master_key.salt,
        ));

        let master = decrypt_secure(
            &decrypter,
            &master_key.entropy_nonce,
            &*master_key.enc_entropy,
        )?;

        let signer = derive_from_master(input.account_id, master)?;
        Ok(signer.sign(data).to_bytes())
    }
}

#[async_trait]
impl SignerStorage for DerivedKeySigner {
    fn load_state(&mut self, data: &str) -> Result<()> {
        self.master_key = serde_json::from_str(data)?;
        Ok(())
    }

    fn store_state(&self) -> String {
        serde_json::to_string(&self.master_key).trust_me()
    }

    fn get_entries(&self) -> Vec<SignerEntry> {
        self.master_key
            .as_ref()
            .map(|key| {
                key.accounts_map
                    .iter()
                    .map(|(public_key, (name, _))| SignerEntry {
                        name: name.clone(),
                        public_key: PublicKey::from_bytes(public_key).trust_me(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn remove_key(&mut self, public_key: &PublicKey) -> bool {
        match &mut self.master_key {
            Some(key) => key.accounts_map.remove(public_key.as_bytes()).is_some(),
            None => false,
        }
    }

    async fn clear(&mut self) {
        if let Some(key) = &mut self.master_key {
            key.accounts_map.clear();
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct MasterKey {
    #[serde(with = "serde_public_key")]
    public_key: PublicKey,
    #[serde(with = "serde_bytes")]
    enc_entropy: Vec<u8>,
    #[serde(with = "serde_bytes")]
    enc_phrase: Vec<u8>,
    #[serde(with = "serde_nonce")]
    entropy_nonce: Nonce,
    #[serde(with = "serde_nonce")]
    phrase_nonce: Nonce,
    #[serde(with = "serde_bytes")]
    salt: Vec<u8>,
    #[serde(with = "serde_accounts_map")]
    accounts_map: AccountsMap,
}

impl MasterKey {
    fn new(password: SecStr, phrase: SecStr, name: String) -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();

        let mut salt = vec![0u8; CREDENTIAL_LEN];
        rng.fill(salt.as_mut_slice())
            .map_err(|_| MasterKeyError::FailedToGenerateRandomBytes)?;

        let mut entropy_nonce = [0u8; NONCE_LENGTH];
        rng.fill(&mut entropy_nonce)
            .map_err(|_| MasterKeyError::FailedToGenerateRandomBytes)?;

        let mut phrase_nonce = [0u8; NONCE_LENGTH];
        rng.fill(&mut phrase_nonce)
            .map_err(|_| MasterKeyError::FailedToGenerateRandomBytes)?;

        let entropy_nonce = Nonce::clone_from_slice(entropy_nonce.as_ref());
        let phrase_nonce = Nonce::clone_from_slice(phrase_nonce.as_ref());

        let key = symmetric_key_from_password(password, &*salt);
        let encryptor = ChaCha20Poly1305::new(&key);
        let phrase = String::from_utf8(phrase.unsecure().to_vec())?;
        let entropy = derive_master_key(&phrase)?;
        let enc_entropy = encrypt(&encryptor, &entropy_nonce, &entropy)?;
        let pair = derive_from_phrase(&phrase, MnemonicType::Labs(0))?;
        let enc_phrase = encrypt(&encryptor, &phrase_nonce, &phrase.as_bytes())?;
        SecStr::new(phrase.into_bytes()).zero_out();

        let mut account_map = AccountsMap::new();
        account_map.insert(pair.public.to_bytes(), (name, 0));

        Ok(Self {
            public_key: pair.public,
            enc_entropy,
            enc_phrase,
            entropy_nonce,
            phrase_nonce,
            salt,
            accounts_map: account_map,
        })
    }
}

type AccountsMap = HashMap<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH], (String, u32)>;

pub struct DerivedKeySignParams {
    pub account_id: u32,
    pub password: SecStr,
}

pub struct DerivedKeyExportParams {
    pub password: SecStr,
}

pub struct DerivedKeyExportOutput {
    pub phrase: SecStr,
}

pub enum DerivedKeyCreateInput {
    Import { phrase: SecStr, password: SecStr },
    Derive { account_id: u32, password: SecStr },
}

mod serde_accounts_map {
    use super::*;

    use serde::de::Error;
    use serde::ser::SerializeMap;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::convert::TryInto;

    pub fn serialize<S>(data: &AccountsMap, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct StoredItem<'a> {
            name: &'a str,
            account_id: u32,
        }

        let mut map = serializer.serialize_map(Some(data.len()))?;
        for (pubkey, (name, account_id)) in data.iter() {
            map.serialize_entry(
                &hex::encode(pubkey),
                &StoredItem {
                    name: name.as_ref(),
                    account_id: *account_id,
                },
            )?;
        }

        map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<AccountsMap, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StoredItem {
            name: String,
            account_id: u32,
        }

        let stored_data = HashMap::<String, StoredItem>::deserialize(deserializer)?;
        stored_data
            .into_iter()
            .map(|(public_key, StoredItem { name, account_id })| {
                let public_key = hex::decode(&public_key)
                    .map_err(D::Error::custom)
                    .and_then(|public_key| {
                        public_key
                            .try_into()
                            .map_err(|_| D::Error::custom("Invalid public key"))
                    })?;
                Ok((public_key, (name, account_id)))
            })
            .collect::<Result<_, _>>()
    }
}

fn derive_from_master(id: u32, master: SecVec<u8>) -> Result<ed25519_dalek::Keypair> {
    use tiny_hderive::bip32;

    let path = format!("m/44'/396'/0'/0/{}", id);
    let key = bip32::ExtendedPrivKey::derive(master.unsecure(), path.as_str())
        .map_err(|_| MasterKeyError::DerivationError)?
        .secret();
    drop(master);
    let secret =
        ed25519_dalek::SecretKey::from_bytes(&key).map_err(|_| MasterKeyError::DerivationError)?;
    let public = ed25519_dalek::PublicKey::from(&secret);
    Ok(ed25519_dalek::Keypair { secret, public })
}

#[derive(Debug, Error)]
enum MasterKeyError {
    #[error("Master key not found")]
    MasterKeyNotFound,
    #[error("Failed to derive account from master key")]
    DerivationError,
    #[error("Failed to encrypt data")]
    FailedToEncryptData,
    #[error("Failed to decrypt data")]
    FailedToDecryptData,
    #[error("Failed to generate random bytes")]
    FailedToGenerateRandomBytes,
}

/// Decrypts data using specified decrypter and nonce
fn decrypt_secure(
    dec: &ChaCha20Poly1305,
    nonce: &Nonce,
    data: &[u8],
) -> Result<SecVec<u8>, MasterKeyError> {
    decrypt(dec, nonce, data).map(SecVec::new)
}

/// Decrypts data using specified decrypter and nonce
fn decrypt(dec: &ChaCha20Poly1305, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>, MasterKeyError> {
    dec.decrypt(nonce, data)
        .map_err(|_| MasterKeyError::FailedToDecryptData)
}

/// Encrypts data using specified encryptor and nonce
fn encrypt(enc: &ChaCha20Poly1305, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>, MasterKeyError> {
    enc.encrypt(nonce, data)
        .map_err(|_| MasterKeyError::FailedToEncryptData)
}

#[cfg(test)]
mod test {
    use super::StoreSigner;
    use crate::crypto::{DerivedKeyCreateInput, DerivedKeySigner};

    #[tokio::test]
    async fn test_creation() {
        let mut empty = DerivedKeySigner::new();
        empty.add_key(
            "lol",
            DerivedKeyCreateInput::Import {
                phrase:
                "pioneer fever hazard scan install wise reform corn bubble leisure amazing note"
                        .to_string()
                        .into(),
                password: "123".to_string().into(),
            },
        ).await.unwrap();
        empty.master_key.unwrap();
    }
}
