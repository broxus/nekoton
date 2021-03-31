pub mod mnemonics;
pub mod stored_key;

use std::collections::hash_map::{self, HashMap};
use std::sync::Arc;

use anyhow::Result;
use dyn_clone::DynClone;
use tokio::sync::{RwLock, RwLockReadGuard};

use self::stored_key::StoredKey;
use super::Storage;
use crate::utils::*;

const STORAGE_KEYSTORE: &str = "keystore";

pub trait UnsignedMessage: DynClone {
    fn hash(&self) -> &[u8];
    fn sign(&self, signature: &[u8; ed25519_dalek::SIGNATURE_LENGTH]) -> Result<SignedMessage>;
}

dyn_clone::clone_trait_object!(UnsignedMessage);

#[derive(Clone)]
pub struct SignedMessage {
    pub message: ton_block::Message,
    pub expire_at: u32,
}

#[derive(Clone)]
pub struct KeyStore {
    storage: Arc<dyn Storage>,
    keys: Arc<RwLock<HashMap<String, StoredKey>>>,
}

impl KeyStore {
    /// Loads full keystore state from the storage. Fails on invalid data
    pub async fn load(storage: Arc<dyn Storage>) -> Result<Self> {
        struct KeysMap(HashMap<String, StoredKey>);

        impl<'de> serde::Deserialize<'de> for KeysMap {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::Error;

                let keys = HashMap::<String, String>::deserialize(deserializer)?;
                let keys = keys
                    .into_iter()
                    .map(|(public_key, stored)| {
                        let stored = StoredKey::from_reader(&mut std::io::Cursor::new(stored))
                            .map_err(|_| D::Error::custom("Failed to deserialize StoredKey"))?;
                        Ok((public_key, stored))
                    })
                    .collect::<Result<_, _>>()?;
                Ok(KeysMap(keys))
            }
        }

        let data = match storage.get(STORAGE_KEYSTORE).await? {
            Some(data) => serde_json::from_str::<KeysMap>(&data)?.0,
            None => Default::default(),
        };

        Ok(Self {
            storage,
            keys: Arc::new(RwLock::new(data)),
        })
    }

    /// Loads full keystore state from the storage. Returns empty keystore on invalid data
    pub async fn load_unchecked(storage: Arc<dyn Storage>) -> Self {
        Self::load(storage.clone()).await.unwrap_or_else(|_| Self {
            storage,
            keys: Arc::new(Default::default()),
        })
    }

    /// Adds new key to the keystore.
    ///
    /// Returns hex-encoded public key, which can be used as key id later
    pub async fn add_key(&self, key: StoredKey) -> Result<String> {
        struct KeysMap<'a>(&'a HashMap<String, StoredKey>);

        impl<'a> serde::Serialize for KeysMap<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(self.0.len()))?;
                for (key, value) in self.0.iter() {
                    map.serialize_entry(key, &value.as_json())?;
                }
                map.end()
            }
        }

        let public_key = hex::encode(key.public_key());

        let new_data = {
            let mut keys = self.keys.write().await;
            match keys.entry(public_key.clone()) {
                hash_map::Entry::Occupied(_) => return Err(KeyStoreError::KeyAlreadyExists.into()),
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(key);
                }
            }
            serde_json::to_string(&KeysMap(&*keys)).trust_me()
        };

        self.storage.set(STORAGE_KEYSTORE, &new_data).await?;

        Ok(public_key)
    }

    /// Removes key from the keystore
    ///
    /// # Arguments
    /// `public_key` - hex encoded public key
    pub async fn remove_key(&self, public_key: &str) -> Option<StoredKey> {
        let mut keys = self.keys.write().await;
        keys.remove(public_key)
    }

    /// Returns handler to the inner keys map
    pub async fn stored_keys(&'_ self) -> RwLockReadGuard<'_, HashMap<String, StoredKey>> {
        self.keys.read().await
    }
}

#[derive(thiserror::Error, Debug)]
pub enum KeyStoreError {
    #[error("Key already exists")]
    KeyAlreadyExists,
    #[error("Failed to generate random bytes")]
    FailedToGenerateRandomBytes(ring::error::Unspecified),
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Failed to decrypt data")]
    FailedToDecryptData,
    #[error("Failed to encrypt data")]
    FailedToEncryptData,
}
