use std::collections::hash_map::{self, HashMap};
use std::convert::TryInto;
use std::io::Read;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use ed25519_dalek::{ed25519, PublicKey};
use serde::{Deserialize, Serialize};

use crate::crypto::{Signer as StoreSigner, SignerEntry, SignerStorage};
use crate::external::LedgerConnection;
use crate::utils::*;

#[derive(Clone)]
pub struct LedgerKeySigner {
    keys: KeysMap,
    connection: Arc<dyn LedgerConnection>,
}

type KeysMap = HashMap<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH], LedgerKey>;

impl LedgerKeySigner {
    pub fn new(connection: Arc<dyn LedgerConnection>) -> Self {
        Self {
            keys: Default::default(),
            connection,
        }
    }

    fn get_key(&self, public_key: &PublicKey) -> Result<&LedgerKey> {
        match self.keys.get(public_key.as_bytes()) {
            Some(key) => Ok(key),
            None => Err(LedgerKeyError::KeyNotFound.into()),
        }
    }
}

#[async_trait]
impl StoreSigner for LedgerKeySigner {
    type CreateKeyInput = LedgerKeyCreateInput;
    type ExportKeyInput = LedgerKeyEmpty;
    type ExportKeyOutput = LedgerKeyEmpty;
    type UpdateKeyInput = LedgerKeyEmpty;
    type SignInput = LedgerKeyPublic;

    async fn add_key(&mut self, name: &str, input: Self::CreateKeyInput) -> Result<PublicKey> {
        let pubkey_bytes = self.connection.get_public_key(input.account).await?;
        let pubkey = ed25519_dalek::PublicKey::from_bytes(&pubkey_bytes)?;

        let key = LedgerKey::new(name, input.account, pubkey)?;

        let public_key = *key.public_key();

        match self.keys.entry(public_key.to_bytes()) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(key);
                Ok(public_key)
            }
            hash_map::Entry::Occupied(_) => return Err(LedgerKeyError::KeyAlreadyExists.into()),
        }
    }

    async fn update_key(&mut self, _input: Self::UpdateKeyInput) -> Result<()> {
        Err(LedgerKeyError::MethodNotSupported.into())
    }

    async fn export_key(&self, _input: Self::ExportKeyInput) -> Result<Self::ExportKeyOutput> {
        Err(LedgerKeyError::MethodNotSupported.into())
    }

    async fn sign(
        &self,
        data: &[u8],
        input: Self::SignInput,
    ) -> Result<[u8; ed25519::SIGNATURE_LENGTH]> {
        let key = self.get_key(&input.public_key)?;
        let signature = self.connection.sign(key.inner.account, data).await?;
        Ok(signature)
    }
}

#[async_trait]
impl SignerStorage for LedgerKeySigner {
    fn load_state(&mut self, data: &str) -> Result<()> {
        let data = serde_json::from_str::<Vec<(String, String)>>(data)?;

        self.keys = data
            .into_iter()
            .map(|(public_key, data)| {
                let public_key = hex::decode(&public_key)?
                    .try_into()
                    .map_err(|_| LedgerKeyError::InvalidPublicKey)?;
                let data = LedgerKey::from_reader(&mut std::io::Cursor::new(data))?;
                Ok((public_key, data))
            })
            .collect::<Result<_>>()?;

        Ok(())
    }

    fn store_state(&self) -> String {
        use serde::ser::SerializeSeq;

        struct StoredData<'a>(&'a KeysMap);
        #[derive(Serialize)]
        struct StoredDataItem<'a>(&'a str, &'a str);

        impl<'a> Serialize for StoredData<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                for (public_key, signer) in self.0.iter() {
                    let public_key = hex::encode(public_key);
                    let signer = signer.as_json();
                    seq.serialize_element(&StoredDataItem(&public_key, &signer))?;
                }
                seq.end()
            }
        }

        serde_json::to_string(&StoredData(&self.keys)).trust_me()
    }

    fn get_entries(&self) -> Vec<SignerEntry> {
        self.keys
            .values()
            .map(|key| SignerEntry {
                name: key.name().to_string(),
                public_key: *key.public_key(),
            })
            .collect()
    }

    async fn remove_key(&mut self, public_key: &PublicKey) -> bool {
        self.keys.remove(public_key.as_bytes()).is_some()
    }

    async fn clear(&mut self) {
        self.keys.clear();
    }
}

pub struct LedgerKeyCreateInput {
    pub account: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LedgerKeyPublic {
    #[serde(with = "crate::utils::serde_public_key")]
    pub public_key: PublicKey,
}

pub struct LedgerKeyEmpty {}

#[derive(Clone)]
pub struct LedgerKey {
    inner: CryptoData,
}

impl LedgerKey {
    pub fn new(name: &str, account: u32, pubkey: PublicKey) -> Result<Self> {
        Ok(Self {
            inner: CryptoData {
                name: name.to_owned(),
                account,
                pubkey,
            },
        })
    }

    pub fn from_reader<T>(reader: T) -> Result<Self>
    where
        T: Read,
    {
        let crypto_data: CryptoData = serde_json::from_reader(reader)?;
        Ok(LedgerKey { inner: crypto_data })
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.inner.pubkey
    }

    pub fn as_json(&self) -> String {
        serde_json::to_string(&self.inner).trust_me()
    }
}

impl std::fmt::Debug for LedgerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner.pubkey)
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct CryptoData {
    name: String,
    account: u32,

    #[serde(with = "serde_public_key")]
    pubkey: PublicKey,
}

#[derive(thiserror::Error, Debug)]
pub enum LedgerKeyError {
    #[error("Key already exists")]
    KeyAlreadyExists,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Method not supported")]
    MethodNotSupported,
}
