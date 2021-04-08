use std::collections::HashMap;
use std::sync::Arc;

use crate::external::Storage;
use crate::storage::{Signer as StoreSigner, SignerEntry, SignerStorage, WithPublicKey};
use anyhow::Result;
use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{PublicKey, Signer};
use secstr::{SecStr, SecVec};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::ser::*;
use crate::utils::TrustMe;

pub type AccountMap = HashMap<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH], u32>;

#[derive(Clone)]
struct MasterKeyStore {
    key: MasterKey,
    storage: Arc<dyn Storage>,
}

#[derive(Clone, Serialize, Deserialize)]
struct MasterKey {
    #[serde(with = "hex_encode")]
    enc_entropy: Vec<u8>,
    #[serde(with = "hex_encode")]
    enc_mnemonics: Vec<u8>,
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

mod hex_map_string {
    use crate::crypto::derived_key::AccountMap;
    use crate::crypto::ser::hex_encode;
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
                    .map_err(|e| D::Error::custom("Failed mapping vec to salt"))?,
                v,
            );
        }
        Ok(new_map)
    }
}

#[async_trait]
impl SignerStorage for MasterKeyStore {
    fn load_state(&mut self, data: &str) -> Result<()> {
        let key = serde_json::from_str(data)?;
        self.key = key;
        Ok(())
    }

    fn store_state(&self) -> String {
        serde_json::to_string(&self.key).trust_me()
    }

    fn get_entries(&self) -> Vec<SignerEntry> {
        self.key.entries.clone()
    }

    async fn remove_key(&mut self, public_key: &PublicKey) -> bool {
        let map = &mut self.key.account_map;
        map.remove(public_key.as_bytes()).is_some()
    }

    async fn clear(&mut self) {
        let map = &mut self.key.account_map;
        map.clear();
        self.key.entries.clear();
    }
}

pub struct MasterKeySignParams {
    pub account_id: u32,
    pub password: SecStr,
}

pub struct MasterKeyCreateInput {
    pub account_id: u32,
    pub password: SecStr,
}

#[async_trait]
impl StoreSigner for MasterKeyStore {
    type CreateKeyInput = MasterKeyCreateInput;
    type SignInput = MasterKeySignParams;

    async fn add_key(&mut self, name: &str, input: Self::CreateKeyInput) -> Result<PublicKey> {
        let decrypter = ChaCha20Poly1305::new(&super::symmetric::symmetric_key_from_password(
            input.password,
            &self.key.salt,
        ));
        let master = decrypt_secure(&decrypter, &self.key.entropy_nonce, &*self.key.enc_entropy)?;
        let public_key = derive_from_master(input.account_id, master)?.public;
        self.key.entries.push(SignerEntry {
            name: name.to_string(),
            public_key,
        });
        Ok(public_key)
    }

    async fn sign(&self, data: &[u8], input: Self::SignInput) -> Result<[u8; 64]> {
        let decrypter = ChaCha20Poly1305::new(&super::symmetric::symmetric_key_from_password(
            input.password,
            &self.key.salt,
        ));

        let master = decrypt_secure(&decrypter, &self.key.entropy_nonce, &*self.key.enc_entropy)?;
        let signer = derive_from_master(input.account_id, master)?;
        Ok(signer.sign(data).to_bytes())
    }
}

fn derive_from_master(id: u32, master: SecVec<u8>) -> Result<ed25519_dalek::Keypair> {
    use tiny_hderive::bip32;

    let path = format!("m/44'/396'/0'/0/{}", id).as_str();
    let key = bip32::ExtendedPrivKey::derive(master.unsecure(), path)
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
