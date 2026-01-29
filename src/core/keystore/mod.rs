use std::any::TypeId;
use std::collections::hash_map::{self, HashMap};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use futures_util::future;
use rand::Rng;
use serde::{Serialize, Serializer};
use tokio::sync::RwLock;

use nekoton_utils::*;

use crate::crypto::{
    EncryptedData, EncryptionAlgorithm, PasswordCache, SharedSecret, Signature, SignatureContext,
    Signer, SignerContext, SignerEntry, SignerStorage,
};
use crate::external::Storage;

pub const KEYSTORE_STORAGE_KEY: &str = "__core__keystore";

pub struct KeyStore {
    state: RwLock<KeyStoreState>,
    storage: Arc<dyn Storage>,
    password_cache: PasswordCache,
}

impl KeyStore {
    pub fn builder() -> KeyStoreBuilder {
        KeyStoreBuilder {
            signers: Default::default(),
            signer_types: Default::default(),
        }
    }

    #[inline(always)]
    pub fn password_cache(&self) -> &PasswordCache {
        &self.password_cache
    }

    pub fn is_password_cached(&self, id: &[u8; 32], duration: Duration) -> bool {
        self.password_cache.contains(id, duration)
    }

    pub async fn reload(&self) -> Result<()> {
        let data = KeyStoreBuilder::load_stored_data(&self.storage).await?;

        // Update state
        {
            let mut state = self.state.write().await;

            let mut entries = HashMap::new();
            for (name, data) in &data {
                if let Some((type_id, (_, storage))) = state
                    .signers
                    .iter_mut()
                    .find(|(_, (signer_name, _))| signer_name == name)
                {
                    storage.load_state(data)?;
                    entries.extend(
                        storage
                            .get_entries()
                            .into_iter()
                            .map(|entry| entry.into_plain(*type_id)),
                    );
                }
            }
            state.entries = entries;
        }

        self.password_cache.reset();

        Ok(())
    }

    pub async fn get_entries(&self) -> Vec<KeyStoreEntry> {
        let state = self.state.read().await;
        state
            .entries
            .values()
            .filter_map(|(type_id, signer_entry)| {
                Some(KeyStoreEntry::from_signer_entry(
                    state.signers.get(type_id)?.0.clone(),
                    signer_entry.clone(),
                ))
            })
            .collect()
    }

    pub async fn add_key<T>(&self, input: T::CreateKeyInput) -> Result<KeyStoreEntry>
    where
        T: Signer,
    {
        let mut state = self.state.write().await;

        let (signer_name, signer): (_, &mut T) = state.get_signer_mut::<T>()?;

        let ctx = SignerContext {
            password_cache: &self.password_cache,
        };
        let signer_entry = signer.add_key(ctx, input).await?;
        state.entries.insert(
            signer_entry.public_key.to_bytes(),
            (TypeId::of::<T>(), signer_entry.clone()),
        );

        self.save(&state.signers).await?;
        Ok(KeyStoreEntry::from_signer_entry(signer_name, signer_entry))
    }

    pub async fn add_keys<T, I>(&self, input: I) -> Result<Vec<KeyStoreEntry>>
    where
        T: Signer,
        I: IntoIterator<Item = T::CreateKeyInput>,
    {
        let mut state = self.state.write().await;

        let ctx = SignerContext {
            password_cache: &self.password_cache,
        };

        let mut entries = Vec::new();

        for input in input {
            let (signer_name, signer): (_, &mut T) = state.get_signer_mut::<T>()?;

            let signer_entry = signer.add_key(ctx, input).await?;
            state.entries.insert(
                signer_entry.public_key.to_bytes(),
                (TypeId::of::<T>(), signer_entry.clone()),
            );

            entries.push(KeyStoreEntry::from_signer_entry(
                signer_name.clone(),
                signer_entry,
            ));
        }

        self.save(&state.signers).await?;
        Ok(entries)
    }

    pub async fn update_key<T>(&self, input: T::UpdateKeyInput) -> Result<KeyStoreEntry>
    where
        T: Signer,
    {
        let mut state = self.state.write().await;

        let (signer_name, signer): (_, &mut T) = state.get_signer_mut::<T>()?;

        let ctx = SignerContext {
            password_cache: &self.password_cache,
        };
        let signer_entry = signer.update_key(ctx, input).await?;
        state.entries.insert(
            signer_entry.public_key.to_bytes(),
            (TypeId::of::<T>(), signer_entry.clone()),
        );

        self.save(&state.signers).await?;
        Ok(KeyStoreEntry::from_signer_entry(signer_name, signer_entry))
    }

    pub async fn export_seed<T>(&self, input: T::ExportSeedInput) -> Result<T::ExportSeedOutput>
    where
        T: Signer,
    {
        let state = self.state.read().await;

        let ctx = SignerContext {
            password_cache: &self.password_cache,
        };
        state.get_signer_ref::<T>()?.export_seed(ctx, input).await
    }

    pub async fn export_keypair<T>(
        &self,
        input: T::ExportKeypairInput,
    ) -> Result<T::ExportKeypairOutput>
    where
        T: Signer,
    {
        let state = self.state.read().await;

        let ctx = SignerContext {
            password_cache: &self.password_cache,
        };
        state
            .get_signer_ref::<T>()?
            .export_keypair(ctx, input)
            .await
    }

    pub async fn get_public_keys<T>(&self, input: T::GetPublicKeys) -> Result<Vec<PublicKey>>
    where
        T: Signer,
    {
        let state = self.state.read().await;

        let ctx = SignerContext {
            password_cache: &self.password_cache,
        };
        state
            .get_signer_ref::<T>()?
            .get_public_keys(ctx, input)
            .await
    }

    pub async fn encrypt<T>(
        &self,
        data: &[u8],
        public_keys: &[ed25519_dalek::PublicKey],
        algorithm: EncryptionAlgorithm,
        input: T::SignInput,
    ) -> Result<Vec<EncryptedData>>
    where
        T: Signer,
    {
        let state = self.state.read().await;

        let ctx = SignerContext {
            password_cache: &self.password_cache,
        };

        let mut result = Vec::with_capacity(public_keys.len());
        for SharedSecret {
            source_public_key,
            recipient_public_key,
            secret,
        } in state
            .get_signer_ref::<T>()?
            .compute_shared_secrets(ctx, public_keys, input)
            .await?
        {
            match algorithm {
                EncryptionAlgorithm::ChaCha20Poly1305 => {
                    use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

                    let nonce = Nonce::from(rand::thread_rng().gen::<[u8; 12]>());
                    let encryptor =
                        ChaCha20Poly1305::new(&Key::clone_from_slice(secret.as_slice()));
                    let data = encrypt(&encryptor, &nonce, data)?;
                    result.push(EncryptedData {
                        algorithm,
                        source_public_key,
                        recipient_public_key,
                        data,
                        nonce: nonce.to_vec(),
                    })
                }
            }
        }
        Ok(result)
    }

    pub async fn decrypt<T>(&self, data: &EncryptedData, input: T::SignInput) -> Result<Vec<u8>>
    where
        T: Signer,
    {
        let state = self.state.read().await;

        let ctx = SignerContext {
            password_cache: &self.password_cache,
        };
        let SharedSecret { secret, .. } = state
            .get_signer_ref::<T>()?
            .compute_shared_secrets(ctx, &[data.source_public_key], input)
            .await?
            .into_iter()
            .next()
            .ok_or(KeyStoreError::SharedSecretError)?;

        match data.algorithm {
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

                let nonce = <[u8; 12]>::try_from(data.nonce.as_slice())
                    .map(Nonce::from)
                    .map_err(|_| KeyStoreError::InvalidNonce)?;
                let decryptor = ChaCha20Poly1305::new(&Key::clone_from_slice(secret.as_slice()));
                let data = decrypt(&decryptor, &nonce, &data.data)?;

                Ok(data)
            }
        }
    }

    pub async fn sign<T>(
        &self,
        data: &[u8],
        signature_ctx: SignatureContext,
        input: T::SignInput,
    ) -> Result<Signature>
    where
        T: Signer,
    {
        let state = self.state.read().await;

        let ctx = SignerContext {
            password_cache: &self.password_cache,
        };
        state
            .get_signer_ref::<T>()?
            .sign(ctx, data, signature_ctx, input)
            .await
    }

    pub async fn remove_key(&self, public_key: &PublicKey) -> Result<Option<KeyStoreEntry>> {
        let mut state = self.state.write().await;

        let signer_id = match state.entries.remove(public_key.as_bytes()) {
            Some((signer_id, _)) => signer_id,
            None => return Ok(None),
        };

        let (signer_name, signer) = match state.signers.get_mut(&signer_id) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let entry = signer.remove_key(public_key).await.map(|signer_entry| {
            KeyStoreEntry::from_signer_entry(signer_name.clone(), signer_entry)
        });

        self.save(&state.signers).await?;
        Ok(entry)
    }

    pub async fn remove_keys(&self, public_keys: &[PublicKey]) -> Result<Vec<KeyStoreEntry>> {
        let mut state = self.state.write().await;

        let mut entries = Vec::new();

        for public_key in public_keys {
            let signer_id = match state.entries.remove(public_key.as_bytes()) {
                Some((signer_id, _)) => signer_id,
                None => continue,
            };

            let (signer_name, signer) = match state.signers.get_mut(&signer_id) {
                Some(entry) => entry,
                None => continue,
            };

            if let Some(signer_entry) = signer.remove_key(public_key).await {
                entries.push(KeyStoreEntry::from_signer_entry(
                    signer_name.clone(),
                    signer_entry,
                ));
            }
        }

        self.save(&state.signers).await?;
        Ok(entries)
    }

    pub async fn clear(&self) -> Result<()> {
        let mut state = self.state.write().await;

        state.entries.clear();
        future::join_all(state.signers.values_mut().map(|(_, signer)| signer.clear())).await;

        self.save(&state.signers).await
    }

    async fn save(&self, signers: &SignersMap) -> Result<()> {
        use serde::ser::SerializeSeq;

        struct StoredData<'a>(&'a SignersMap);

        #[derive(Serialize)]
        struct StoredDataItem<'a>(&'a str, &'a str);

        impl Serialize for StoredData<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                for (name, signer) in self.0.values() {
                    seq.serialize_element(&StoredDataItem(name.as_str(), &signer.store_state()))?;
                }
                seq.end()
            }
        }

        let data = serde_json::to_string(&StoredData(signers))?;
        self.storage.set(KEYSTORE_STORAGE_KEY, &data).await
    }
}

struct KeyStoreState {
    signers: SignersMap,
    entries: EntriesMap,
}

type SignersMap = HashMap<TypeId, (String, Box<dyn SignerStorage>)>;
type EntriesMap = HashMap<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH], (TypeId, SignerEntry)>;

impl KeyStoreState {
    fn get_signer_ref<T>(&self) -> Result<&T>
    where
        T: Signer,
    {
        let signer = self
            .signers
            .get(&TypeId::of::<T>())
            .and_then(|(_, signer)| signer.downcast_ref::<T>())
            .ok_or(KeyStoreError::UnsupportedSigner)?;
        Ok(signer)
    }

    fn get_signer_mut<T>(&mut self) -> Result<(String, &mut T)>
    where
        T: Signer,
    {
        let signer = self
            .signers
            .get_mut(&TypeId::of::<T>())
            .and_then(|(name, signer)| {
                signer
                    .downcast_mut::<T>()
                    .map(|signer| (name.clone(), signer))
            })
            .ok_or(KeyStoreError::UnsupportedSigner)?;
        Ok(signer)
    }
}

impl SignerEntry {
    fn into_plain(
        self,
        type_id: TypeId,
    ) -> ([u8; ed25519_dalek::PUBLIC_KEY_LENGTH], (TypeId, Self)) {
        (self.public_key.to_bytes(), (type_id, self))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct KeyStoreEntry {
    pub signer_name: String,
    pub name: String,
    #[serde(with = "nekoton_utils::serde_public_key")]
    pub public_key: PublicKey,
    #[serde(with = "nekoton_utils::serde_public_key")]
    pub master_key: PublicKey,
    pub account_id: u16,
}

impl KeyStoreEntry {
    fn from_signer_entry(signer_name: String, signer_entry: SignerEntry) -> Self {
        Self {
            signer_name,
            name: signer_entry.name,
            public_key: signer_entry.public_key,
            master_key: signer_entry.master_key,
            account_id: signer_entry.account_id,
        }
    }
}

pub struct KeyStoreBuilder {
    signers: HashMap<String, (Box<dyn SignerStorage>, TypeId)>,
    signer_types: HashSet<TypeId>,
}

type BuilderSignersMap = HashMap<String, (Box<dyn SignerStorage>, TypeId)>;

impl KeyStoreBuilder {
    pub fn with_signer<T>(mut self, name: &str, signer: T) -> Result<Self, KeyStoreError>
    where
        T: Signer,
    {
        let type_id = TypeId::of::<T>();
        if !self.signer_types.insert(type_id) {
            return Err(KeyStoreError::DuplicateSignerType);
        }

        match self.signers.entry(name.to_owned()) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert((Box::new(signer), type_id));
            }
            hash_map::Entry::Occupied(_) => return Err(KeyStoreError::DuplicateSignerType),
        }

        Ok(self)
    }

    pub fn verify(mut self, data: &str) -> Result<()> {
        let data = serde_json::from_str::<Vec<(String, String)>>(data)?;
        for (name, data) in data {
            if let Some((storage, _)) = self.signers.get_mut(&name) {
                storage.load_state(&data)?;
            }
        }
        Ok(())
    }

    pub async fn load(mut self, storage: Arc<dyn Storage>) -> Result<KeyStore> {
        let data = Self::load_stored_data(&storage).await?;

        let mut entries = HashMap::new();

        for (name, data) in data {
            if let Some((storage, type_id)) = self.signers.get_mut(&name) {
                storage.load_state(&data)?;

                entries.extend(
                    storage
                        .get_entries()
                        .into_iter()
                        .map(|entry| entry.into_plain(*type_id)),
                );
            }
        }

        Ok(KeyStore {
            state: RwLock::new(KeyStoreState {
                signers: transpose_signers(self.signers),
                entries,
            }),
            storage,
            password_cache: PasswordCache::new(),
        })
    }

    pub async fn load_unchecked(mut self, storage: Arc<dyn Storage>) -> KeyStore {
        let data = Self::load_stored_data(&storage).await.unwrap_or_default();

        let mut entries = HashMap::new();

        for (name, data) in data {
            if let Some((storage, type_id)) = self.signers.get_mut(&name) {
                if storage.load_state(&data).is_ok() {
                    entries.extend(
                        storage
                            .get_entries()
                            .into_iter()
                            .map(|entry| entry.into_plain(*type_id)),
                    );
                }
            }
        }

        KeyStore {
            state: RwLock::new(KeyStoreState {
                signers: transpose_signers(self.signers),
                entries,
            }),
            storage,
            password_cache: PasswordCache::new(),
        }
    }

    async fn load_stored_data(storage: &Arc<dyn Storage>) -> Result<Vec<(String, String)>> {
        match storage.get(KEYSTORE_STORAGE_KEY).await? {
            Some(data) => {
                let data = serde_json::from_str(&data)?;
                Ok(data)
            }
            None => Ok(Default::default()),
        }
    }
}

fn transpose_signers(signers: BuilderSignersMap) -> SignersMap {
    signers
        .into_iter()
        .map(|(name, (signer, type_id))| (type_id, (name, signer)))
        .collect()
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum KeyStoreError {
    #[error("Duplicate signer name")]
    DuplicateSignerName,
    #[error("Duplicate signer type")]
    DuplicateSignerType,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Unsupported signer")]
    UnsupportedSigner,
    #[error("Failed to compute shared secret")]
    SharedSecretError,
    #[error("Invalid nonce")]
    InvalidNonce,
}

#[cfg(test)]
mod tests {
    use crate::crypto::{
        Bip39MnemonicData, DerivedKeyCreateInput, DerivedKeyPassword, DerivedKeySigner,
        EncryptedKeyCreateInput, EncryptedKeyPassword, EncryptedKeySigner, MnemonicType, Password,
        PasswordCacheBehavior,
    };
    use std::collections::HashMap;

    use super::*;

    #[derive(Default)]
    struct TestStorage(parking_lot::Mutex<HashMap<String, String>>);

    #[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
    #[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
    impl Storage for TestStorage {
        async fn get(&self, key: &str) -> Result<Option<String>> {
            Ok(self.0.lock().get(key).cloned())
        }

        async fn set(&self, key: &str, value: &str) -> Result<()> {
            self.set_unchecked(key, value);
            Ok(())
        }

        fn set_unchecked(&self, key: &str, value: &str) {
            self.0.lock().insert(key.to_string(), value.to_string());
        }

        async fn remove(&self, key: &str) -> Result<()> {
            self.remove_unchecked(key);
            Ok(())
        }

        fn remove_unchecked(&self, key: &str) {
            self.0.lock().remove(key);
        }
    }

    const TEST_MNEMONICS: [&str; 2] = [
        "admit cheap engage ancient audit drink mammal mobile fashion aspect rapid else",
        "stuff chuckle dirt pig health refuse foam liquid around cream undo forum",
    ];

    #[tokio::test]
    async fn correct_encryption() {
        let storage = Arc::new(TestStorage::default());

        let keystore = KeyStore::builder()
            .with_signer("master_key", DerivedKeySigner::new())
            .unwrap()
            .with_signer("encrypted_key", EncryptedKeySigner::new())
            .unwrap()
            .load(storage)
            .await
            .unwrap();

        let useless_password = Password::Explicit {
            password: "test".into(),
            cache_behavior: PasswordCacheBehavior::Store(Duration::from_secs(1000)),
        };

        let first_key = keystore
            .add_key::<DerivedKeySigner>(DerivedKeyCreateInput::Import {
                key_name: None,
                phrase: TEST_MNEMONICS[0].into(),
                password: useless_password.clone(),
            })
            .await
            .unwrap();

        let second_key = keystore
            .add_key::<EncryptedKeySigner>(EncryptedKeyCreateInput {
                name: None,
                phrase: TEST_MNEMONICS[1].into(),
                mnemonic_type: MnemonicType::Bip39(Bip39MnemonicData::labs_old(0)),
                password: useless_password.clone(),
            })
            .await
            .unwrap();

        const TEST_DATA: &[u8] = b"Hello world!";

        // Check encryption (first -> second)
        let encrypted_data = keystore
            .encrypt::<DerivedKeySigner>(
                TEST_DATA,
                &[second_key.public_key],
                EncryptionAlgorithm::ChaCha20Poly1305,
                DerivedKeyPassword::ByPublicKey {
                    master_key: first_key.master_key,
                    public_key: first_key.public_key,
                    password: Password::FromCache,
                },
            )
            .await
            .unwrap();
        assert_eq!(encrypted_data.len(), 1);

        let encrypted_data = encrypted_data[0].clone();
        assert!(matches!(
            encrypted_data.algorithm,
            EncryptionAlgorithm::ChaCha20Poly1305
        ));
        assert_eq!(encrypted_data.source_public_key, first_key.public_key);
        assert_eq!(encrypted_data.recipient_public_key, second_key.public_key);
        assert!(!encrypted_data.data.is_empty());

        // Check decryption (first -> second)
        let data = keystore
            .decrypt::<EncryptedKeySigner>(
                &encrypted_data,
                EncryptedKeyPassword {
                    public_key: second_key.public_key,
                    password: Password::FromCache,
                },
            )
            .await
            .unwrap();
        assert_eq!(data, TEST_DATA);
    }
}
