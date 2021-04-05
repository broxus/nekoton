use std::collections::hash_map::{self, HashMap};
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{RwLock, RwLockReadGuard};

use crate::crypto::EncryptedKey;
use crate::external::Storage;
use crate::utils::*;

const STORAGE_KEYSTORE: &str = "keystore";

pub struct KeyStore {
    storage: Arc<dyn Storage>,
    keys: RwLock<HashMap<String, EncryptedKey>>,
}

impl KeyStore {
    /// Loads full keystore state from the storage. Fails on invalid data
    pub async fn load(storage: Arc<dyn Storage>) -> Result<Self> {
        struct KeysMap(HashMap<String, EncryptedKey>);

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
                        let stored =
                            EncryptedKey::from_reader(&mut std::io::Cursor::new(stored))
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
            keys: RwLock::new(data),
        })
    }

    /// Loads full keystore state from the storage. Returns empty keystore on invalid data
    pub async fn load_unchecked(storage: Arc<dyn Storage>) -> Self {
        Self::load(storage.clone()).await.unwrap_or_else(|_| Self {
            storage,
            keys: Default::default(),
        })
    }

    /// Adds new key to the keystore.
    ///
    /// Returns hex-encoded public key, which can be used as key id later
    pub async fn add_key(&self, key: EncryptedKey) -> Result<String> {
        let public_key = hex::encode(key.public_key());

        let mut keys = self.keys.write().await;
        match keys.entry(public_key.clone()) {
            hash_map::Entry::Occupied(_) => return Err(KeyStoreError::KeyAlreadyExists.into()),
            hash_map::Entry::Vacant(entry) => {
                entry.insert(key);
            }
        }

        self.save(&*keys).await?;
        Ok(public_key)
    }

    /// Removes key from the keystore
    ///
    /// # Arguments
    /// `public_key` - hex encoded public key
    pub async fn remove_key(&self, public_key: &str) -> Result<Option<EncryptedKey>> {
        let mut keys = self.keys.write().await;
        let result = keys.remove(public_key);

        self.save(&*keys).await?;
        Ok(result)
    }

    /// Removes all keys
    pub async fn clear(&self) -> Result<()> {
        self.storage.remove(STORAGE_KEYSTORE).await?;
        self.keys.write().await.clear();
        Ok(())
    }

    /// Returns handler to the inner keys map
    pub async fn stored_keys(&'_ self) -> RwLockReadGuard<'_, HashMap<String, EncryptedKey>> {
        self.keys.read().await
    }

    async fn save(&self, keys: &HashMap<String, EncryptedKey>) -> Result<()> {
        struct KeysMap<'a>(&'a HashMap<String, EncryptedKey>);

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

        let data = serde_json::to_string(&KeysMap(keys)).trust_me();
        self.storage.set(STORAGE_KEYSTORE, &data).await
    }
}

#[derive(thiserror::Error, Debug)]
enum KeyStoreError {
    #[error("Key already exists")]
    KeyAlreadyExists,
}
