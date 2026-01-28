use std::collections::hash_map::{self, HashMap};
use std::convert::TryInto;
use std::io::Read;
use std::sync::Arc;

use anyhow::Result;
use ed25519_dalek::PublicKey;
use serde::{Deserialize, Serialize};

use nekoton_utils::*;

use super::{
    default_key_name, SharedSecret, Signer as StoreSigner, SignerContext, SignerEntry,
    SignerStorage,
};
use crate::core::ton_wallet::WalletType;
use crate::crypto::signature_domain::SignatureDomain;
use crate::external::{LedgerConnection, LedgerSignatureContext};

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

    fn get_key_mut(&mut self, public_key: &PublicKey) -> Result<&mut LedgerKey> {
        match self.keys.get_mut(public_key.as_bytes()) {
            Some(key) => Ok(key),
            None => Err(LedgerKeyError::KeyNotFound.into()),
        }
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
impl StoreSigner for LedgerKeySigner {
    type CreateKeyInput = LedgerKeyCreateInput;
    type ExportSeedInput = ();
    type ExportSeedOutput = ();
    type ExportKeypairInput = ();
    type ExportKeypairOutput = ();
    type GetPublicKeys = LedgerKeyGetPublicKeys;
    type UpdateKeyInput = LedgerUpdateKeyInput;
    type SignInput = LedgerSignInput;

    async fn add_key(
        &mut self,
        _: SignerContext<'_>,
        input: Self::CreateKeyInput,
    ) -> Result<SignerEntry> {
        let master_key = PublicKey::from_bytes(&self.connection.get_public_key(0).await?)?;
        let pubkey_bytes = self.connection.get_public_key(input.account_id).await?;
        let public_key = PublicKey::from_bytes(&pubkey_bytes)?;

        let name = input
            .name
            .unwrap_or_else(|| default_key_name(public_key.as_bytes()));

        let key = LedgerKey::new(name, input.account_id, public_key, master_key)?;
        let name = key.name.clone();
        match self.keys.entry(public_key.to_bytes()) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(key);
                Ok(SignerEntry {
                    name,
                    public_key,
                    master_key,
                    account_id: input.account_id,
                })
            }
            hash_map::Entry::Occupied(_) => return Err(LedgerKeyError::KeyAlreadyExists.into()),
        }
    }

    async fn update_key(
        &mut self,
        _: SignerContext<'_>,
        input: Self::UpdateKeyInput,
    ) -> Result<SignerEntry> {
        match input {
            Self::UpdateKeyInput::Rename { public_key, name } => {
                let key = self.get_key_mut(&public_key)?;
                key.name = name.clone();
                Ok(SignerEntry {
                    name,
                    public_key,
                    master_key: key.master_key,
                    account_id: key.account_id,
                })
            }
        }
    }

    async fn export_seed(
        &self,
        _: SignerContext<'_>,
        _input: Self::ExportSeedInput,
    ) -> Result<Self::ExportSeedOutput> {
        Err(LedgerKeyError::MethodNotSupported.into())
    }

    async fn export_keypair(
        &self,
        _: SignerContext<'_>,
        _input: Self::ExportKeypairInput,
    ) -> Result<Self::ExportKeypairOutput> {
        Err(LedgerKeyError::MethodNotSupported.into())
    }

    async fn get_public_keys(
        &self,
        _: SignerContext<'_>,
        input: Self::GetPublicKeys,
    ) -> Result<Vec<PublicKey>> {
        let mut result = Vec::with_capacity(input.limit as usize);
        for account_id in input.offset..input.offset.saturating_add(input.limit) {
            result.push(PublicKey::from_bytes(
                &self.connection.get_public_key(account_id).await?,
            )?);
        }
        Ok(result)
    }

    async fn compute_shared_secrets(
        &self,
        _: SignerContext<'_>,
        _: &[PublicKey],
        _: Self::SignInput,
    ) -> Result<Vec<SharedSecret>> {
        Err(LedgerKeyError::MethodNotSupported.into())
    }

    async fn sign(
        &self,
        _: SignerContext<'_>,
        data: &[u8],
        signature_domain: SignatureDomain,
        input: Self::SignInput,
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]> {
        let key = self.get_key(&input.public_key)?;
        let signature = match input.context {
            None => {
                self.connection
                    .sign(key.account_id, signature_domain, data)
                    .await?
            }
            Some(context) => {
                self.connection
                    .sign_transaction(
                        key.account_id,
                        input.wallet.try_into()?,
                        signature_domain,
                        data,
                        &context,
                    )
                    .await?
            }
        };

        Ok(signature)
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
impl SignerStorage for LedgerKeySigner {
    fn load_state(&mut self, data: &str) -> Result<()> {
        let data = serde_json::from_str::<Vec<(String, String)>>(data)?;

        self.keys = data
            .into_iter()
            .map(|(public_key, data)| {
                let public_key = hex::decode(public_key)?
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

        impl Serialize for StoredData<'_> {
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
                name: key.name.clone(),
                public_key: key.public_key,
                master_key: key.master_key,
                account_id: key.account_id,
            })
            .collect()
    }

    async fn remove_key(&mut self, public_key: &PublicKey) -> Option<SignerEntry> {
        let key = self.keys.remove(public_key.as_bytes())?;
        Some(SignerEntry {
            name: key.name.clone(),
            public_key: key.public_key,
            master_key: key.master_key,
            account_id: key.account_id,
        })
    }

    async fn clear(&mut self) {
        self.keys.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerKeyCreateInput {
    pub name: Option<String>,
    pub account_id: u16,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LedgerKeyGetPublicKeys {
    pub offset: u16,
    pub limit: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum LedgerUpdateKeyInput {
    #[serde(rename_all = "camelCase")]
    Rename {
        #[serde(with = "serde_public_key")]
        public_key: PublicKey,
        name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerSignInput {
    pub wallet: WalletType,
    #[serde(with = "serde_public_key")]
    pub public_key: PublicKey,
    #[serde(default)]
    pub context: Option<LedgerSignatureContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerKey {
    pub name: String,

    pub account_id: u16,

    #[serde(with = "serde_public_key")]
    pub public_key: PublicKey,

    #[serde(with = "serde_public_key")]
    pub master_key: PublicKey,
}

impl LedgerKey {
    pub fn new(
        name: String,
        account_id: u16,
        public_key: PublicKey,
        master_key: PublicKey,
    ) -> Result<Self> {
        Ok(Self {
            name,
            account_id,
            public_key,
            master_key,
        })
    }

    pub fn from_reader<T>(reader: T) -> Result<Self>
    where
        T: Read,
    {
        let key: Self = serde_json::from_reader(reader)?;
        Ok(key)
    }

    pub fn as_json(&self) -> String {
        serde_json::to_string(&self).trust_me()
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
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

mod test {}
