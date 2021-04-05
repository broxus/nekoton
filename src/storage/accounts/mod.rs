use std::collections::btree_map::{self, BTreeMap};
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, RwLockReadGuard};
use ton_block::MsgAddressInt;

use crate::core::models::*;
use crate::core::ton_wallet;
use crate::external::Storage;
use crate::utils::*;

const STORAGE_ACCOUNTS: &str = "accounts";

pub struct AccountsStorage {
    storage: Arc<dyn Storage>,
    accounts: RwLock<(AssetsMap, Option<String>)>,
}

type AssetsMap = BTreeMap<String, AssetsList>;

impl AccountsStorage {
    /// Loads full accounts storage state. Fails on invalid data
    pub async fn load(storage: Arc<dyn Storage>) -> Result<Self> {
        struct StoredAssetsMap(AssetsMap);

        impl<'de> serde::Deserialize<'de> for StoredAssetsMap {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::Error;

                let accounts = HashMap::<String, String>::deserialize(deserializer)?;
                let accounts = accounts
                    .into_iter()
                    .map(|(public_key, assets)| {
                        let assets = serde_json::from_str(&assets)
                            .map_err(|_| D::Error::custom("Failed to deserialize AssetsList"))?;
                        Ok((public_key, assets))
                    })
                    .collect::<Result<_, _>>()?;
                Ok(StoredAssetsMap(accounts))
            }
        }

        #[derive(Deserialize)]
        struct StoredData {
            assets: StoredAssetsMap,
            #[serde(default)]
            current_account: Option<String>,
        }

        let data = match storage.get(STORAGE_ACCOUNTS).await? {
            Some(data) => {
                let data = serde_json::from_str::<StoredData>(&data)?;
                let assets = data.assets.0;
                let current_account = data
                    .current_account
                    .and_then(|current| {
                        if assets.contains_key(&current) {
                            Some(current)
                        } else {
                            None
                        }
                    })
                    .or_else(|| assets.keys().next().cloned());

                (assets, current_account)
            }
            None => (Default::default(), None),
        };

        Ok(Self {
            storage,
            accounts: RwLock::new(data),
        })
    }

    /// Loads full accounts storage state. Returns empty state on invalid data
    pub async fn load_unchecked(storage: Arc<dyn Storage>) -> Self {
        Self::load(storage.clone()).await.unwrap_or_else(|_| Self {
            storage,
            accounts: Default::default(),
        })
    }

    pub async fn set_current_account(&self, address: &str) -> Result<()> {
        let (assets, current_account) = &mut *self.accounts.write().await;
        if !assets.contains_key(address) {
            return Err(AccountsStorageError::AccountNotFound.into());
        }

        *current_account = Some(address.to_owned());

        self.save(assets, current_account).await?;
        Ok(())
    }

    /// Add account
    pub async fn add_account(
        &self,
        name: &str,
        public_key: ed25519_dalek::PublicKey,
        contract: ton_wallet::ContractType,
        update_current: bool,
    ) -> Result<String> {
        let address =
            ton_wallet::compute_address(&public_key, contract, ton_wallet::DEFAULT_WORKCHAIN);
        let key = address.to_string();

        let (accounts, current_account) = &mut *self.accounts.write().await;
        match accounts.entry(key.clone()) {
            btree_map::Entry::Occupied(_) => {
                return Err(AccountsStorageError::AccountAlreadyExists.into())
            }
            btree_map::Entry::Vacant(entry) => entry.insert(AssetsList {
                name: name.to_owned(),
                ton_wallet: TonWalletAsset {
                    address,
                    public_key,
                    contract,
                },
                token_wallets: Vec::new(),
                depools: Vec::new(),
            }),
        };

        if update_current {
            *current_account = Some(key.clone());
        }

        self.save(accounts, current_account).await?;
        Ok(key)
    }

    /// Removes specified from the storage and resets current account if needed
    pub async fn remove_account(&self, address: &str) -> Result<Option<AssetsList>> {
        let (assets, current_account) = &mut *self.accounts.write().await;
        let result = assets.remove(address);

        if result.is_some()
            && matches!(current_account, Some(current_account) if address == current_account)
        {
            *current_account = None;
        }

        self.save(assets, current_account).await?;
        Ok(result)
    }

    /// Removes all accounts and resets current account
    pub async fn clear(&self) -> Result<()> {
        self.storage.remove(STORAGE_ACCOUNTS).await?;

        let (assets, keys) = &mut *self.accounts.write().await;
        assets.clear();
        *keys = None;

        Ok(())
    }

    /// Returns handler to the inner data
    pub async fn stored_data(&'_ self) -> StoredAccountsData<'_> {
        StoredAccountsData(self.accounts.read().await)
    }

    async fn save(&self, assets: &AssetsMap, current_account: &Option<String>) -> Result<()> {
        struct StoredAssetsMap<'a>(&'a AssetsMap);

        impl<'a> serde::Serialize for StoredAssetsMap<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(self.0.len()))?;
                for (key, value) in self.0.iter() {
                    map.serialize_entry(key, &serde_json::to_string(value).trust_me())?;
                }
                map.end()
            }
        }

        #[derive(Serialize)]
        struct StoredData<'a> {
            assets: StoredAssetsMap<'a>,
            #[serde(skip_serializing_if = "Option::is_none")]
            current_account: &'a Option<String>,
        }

        let data = serde_json::to_string(&StoredData {
            assets: StoredAssetsMap(assets),
            current_account,
        })
        .trust_me();
        self.storage.set(STORAGE_ACCOUNTS, &data).await
    }
}

pub struct StoredAccountsData<'a>(RwLockReadGuard<'a, (AssetsMap, Option<String>)>);

impl<'a> StoredAccountsData<'a> {
    pub fn accounts(&self) -> &AssetsMap {
        &(*self.0).0
    }

    pub fn current_account(&self) -> &Option<String> {
        &(*self.0).1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetsList {
    pub name: String,
    pub ton_wallet: TonWalletAsset,
    pub token_wallets: Vec<TokenWalletAsset>,
    pub depools: Vec<DePoolAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TonWalletAsset {
    #[serde(with = "serde_address")]
    pub address: MsgAddressInt,
    #[serde(with = "serde_public_key")]
    pub public_key: ed25519_dalek::PublicKey,
    pub contract: ton_wallet::ContractType,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenWalletAsset {
    pub symbol: Symbol,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DePoolAsset {
    #[serde(with = "serde_address")]
    pub address: MsgAddressInt,
}

#[derive(thiserror::Error, Debug)]
enum AccountsStorageError {
    #[error("Account already exists")]
    AccountAlreadyExists,
    #[error("Account not found")]
    AccountNotFound,
}
