use std::collections::HashMap;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

use crate::storage::{Signer as StoreSigner, SignerEntry, SignerStorage};
use anyhow::Result;
use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{PublicKey, Signer};
use secstr::{SecStr, SecVec};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::ser::*;
use crate::crypto::symmetric::symmetric_key_from_password;
use crate::crypto::{derive_from_phrase, derive_master_key, MnemonicType};
use crate::utils::TrustMe;
use ring::digest;
use ring::rand::SecureRandom;

pub type AccountMap = HashMap<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH], u32>;

#[derive(Clone, Serialize, Deserialize)]
struct MasterKey {
    #[serde(with = "hex_encode")]
    enc_entropy: Vec<u8>,
    #[serde(with = "hex_encode")]
    enc_phrase: Vec<u8>,
    #[serde(with = "hex_nonce")]
    entropy_nonce: Nonce,
    #[serde(with = "hex_nonce")]
    mnemonic_nonce: Nonce,
    #[serde(with = "hex_encode")]
    salt: Vec<u8>,
    #[serde(with = "hex_map_string")]
    account_map: AccountMap,
    #[serde(skip)]
    entries: Vec<SignerEntry>,
}

impl MasterKey {
    fn new(password: SecStr, phrase: SecStr, name: String) -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();
        let mut salt = vec![0u8; CREDENTIAL_LEN];
        rng.fill(salt.as_mut_slice())
            .map_err(|_| MasterKeyError::FailedToGenerateRandomBytes)?;
        let mut entropy_nonce = [0u8; 12];
        let mut mnemonic_nonce = [0u8; 12];

        rng.fill(&mut entropy_nonce)
            .map_err(|_| MasterKeyError::FailedToGenerateRandomBytes)?;
        rng.fill(&mut mnemonic_nonce)
            .map_err(|_| MasterKeyError::FailedToGenerateRandomBytes)?;

        let entropy_nonce = Nonce::clone_from_slice(entropy_nonce.as_ref());
        let mnemonic_nonce = Nonce::clone_from_slice(mnemonic_nonce.as_ref());

        let key = symmetric_key_from_password(password, &*salt);
        let encryptor = ChaCha20Poly1305::new(&key);
        let phrase = phrase.to_string();
        let entropy = derive_master_key(&phrase)?;
        let enc_entropy = encrypt(&encryptor, &entropy_nonce, &entropy)?;
        let pair = derive_from_phrase(&phrase, MnemonicType::Labs(0))?;
        let enc_phrase = encrypt(&encryptor, &mnemonic_nonce, &phrase.as_bytes())?;
        SecStr::new(phrase.into_bytes()).zero_out();
        let mut account_map = AccountMap::new();
        account_map.insert(pair.public.to_bytes(), 0);
        let entry = SignerEntry {
            name,
            public_key: pair.public,
        };
        let entries = vec![entry];

        Ok(Self {
            enc_entropy,
            enc_phrase,
            entropy_nonce,
            mnemonic_nonce,
            salt,
            account_map,
            entries,
        })
    }
}

mod hex_map_string {
    use crate::crypto::derived_key::AccountMap;
    use serde::de::Error;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::convert::TryInto;

    pub fn serialize<S>(data: &AccountMap, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let d: HashMap<_, _> = data.iter().map(|x| (hex::encode(x.0), x.1)).collect();
        d.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<AccountMap, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map: HashMap<String, u32> = HashMap::deserialize(deserializer)?;
        let mut new_map = HashMap::with_capacity(map.len());
        for (k, v) in map {
            new_map.insert(
                hex::decode(k)
                    .map_err(|e| D::Error::custom(e.to_string()))?
                    .try_into()
                    .map_err(|_e| D::Error::custom("Failed mapping vec to salt"))?,
                v,
            );
        }
        Ok(new_map)
    }
}

#[async_trait]
impl SignerStorage for MasterKey {
    fn load_state(&mut self, data: &str) -> Result<()> {
        let key: MasterKey = serde_json::from_str(data)?;
        *self = key;
        Ok(())
    }

    fn store_state(&self) -> String {
        serde_json::to_string(&self).trust_me()
    }

    fn get_entries(&self) -> Vec<SignerEntry> {
        self.entries.clone()
    }

    async fn remove_key(&mut self, public_key: &PublicKey) -> bool {
        let map = &mut self.account_map;
        map.remove(public_key.as_bytes()).is_some()
    }

    async fn clear(&mut self) {
        let map = &mut self.account_map;
        map.clear();
        self.entries.clear();
    }
}

pub struct MasterKeySignParams {
    pub account_id: u32,
    pub password: SecStr,
}

pub enum MasterKeyCreateInput {
    AddAccount { account_id: u32, password: SecStr },
    Restore { mnemonics: SecStr, password: SecStr },
}

#[async_trait]
impl StoreSigner for MasterKey {
    type CreateKeyInput = MasterKeyCreateInput;
    type SignInput = MasterKeySignParams;

    async fn add_key(&mut self, name: &str, input: Self::CreateKeyInput) -> Result<PublicKey> {
        let public = match input as MasterKeyCreateInput {
            MasterKeyCreateInput::AddAccount {
                account_id,
                password,
            } => {
                let decrypter = ChaCha20Poly1305::new(
                    &super::symmetric::symmetric_key_from_password(password, &self.salt),
                );
                let master = decrypt_secure(&decrypter, &self.entropy_nonce, &*self.enc_entropy)?;
                let public_key = derive_from_master(account_id, master)?.public;
                self.entries.push(SignerEntry {
                    name: name.to_string(),
                    public_key,
                });
                public_key
            }
            MasterKeyCreateInput::Restore {
                mnemonics: phrase,
                password,
            } => {
                let key = MasterKey::new(password, phrase, name.to_string())?;
                *self = key;
                self.entries[0].public_key
            }
        };
        Ok(public)
    }

    async fn sign(&self, data: &[u8], input: Self::SignInput) -> Result<[u8; 64]> {
        let decrypter = ChaCha20Poly1305::new(&super::symmetric::symmetric_key_from_password(
            input.password,
            &self.salt,
        ));

        let master = decrypt_secure(&decrypter, &self.entropy_nonce, &*self.enc_entropy)?;
        let signer = derive_from_master(input.account_id, master)?;
        Ok(signer.sign(data).to_bytes())
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
