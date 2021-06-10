use std::collections::btree_map::{self, BTreeMap};
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, RwLockReadGuard};
use ton_block::MsgAddressInt;

use crate::core::ton_wallet;
use crate::external::Storage;
use crate::utils::*;

const STORAGE_ACCOUNTS: &str = "__core__accounts";

const DEFAULT_NETWORK_GROUP: &str = "mainnet";

pub struct AccountsStorage {
    storage: Arc<dyn Storage>,
    accounts: RwLock<AssetsMap>,
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
                        let assets = serde_json::from_str::<AssetsList>(&assets)
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
        }

        let data = match storage.get(STORAGE_ACCOUNTS).await? {
            Some(data) => serde_json::from_str::<StoredData>(&data)?.assets.0,
            None => Default::default(),
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

    /// Add account. It can later be fetched by ton wallet address
    pub async fn add_account(
        &self,
        name: &str,
        public_key: ed25519_dalek::PublicKey,
        contract: ton_wallet::ContractType,
        owners: ed25519_dalek::PublicKey,
    ) -> Result<AssetsList> {
        let address =
            ton_wallet::compute_address(&public_key, contract, ton_wallet::DEFAULT_WORKCHAIN);
        let key = address.to_string();

        let accounts = &mut *self.accounts.write().await;
        let assets_list = match accounts.entry(key.clone()) {
            btree_map::Entry::Occupied(_) => {
                return Err(AccountsStorageError::AccountAlreadyExists.into())
            }
            btree_map::Entry::Vacant(entry) => entry
                .insert(AssetsList {
                    name: name.to_owned(),
                    ton_wallet: TonWalletAsset {
                        address,
                        public_key,
                        contract,
                        owners,
                    },
                    additional_assets: Default::default(),
                })
                .clone(),
        };

        self.save(accounts).await?;
        Ok(assets_list)
    }

    pub async fn add_token_wallet(
        &self,
        account: &str,
        network_group: &str,
        root_token_contract: MsgAddressInt,
    ) -> Result<AssetsList> {
        use std::collections::hash_map;

        let assets = &mut *self.accounts.write().await;

        let (entry, should_save) = match assets.get_mut(account) {
            Some(entry) => {
                let should_save = match entry.additional_assets.entry(network_group.to_owned()) {
                    hash_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().add_token_wallet(root_token_contract)
                    }
                    hash_map::Entry::Vacant(entry) => {
                        entry.insert(AdditionalAssets::with_token_wallet(root_token_contract));
                        true
                    }
                };

                (entry.clone(), should_save)
            }
            None => return Err(AccountsStorageError::AccountNotFound.into()),
        };

        if should_save {
            self.save(assets).await?;
        }
        Ok(entry)
    }

    pub async fn remove_token_wallet(
        &self,
        account: &str,
        network_group: &str,
        root_token_contract: &MsgAddressInt,
    ) -> Result<AssetsList> {
        let assets = &mut *self.accounts.write().await;

        let (entry, should_save) = match assets.get_mut(account) {
            Some(entry) => {
                let additional_assets = match entry.additional_assets.get_mut(network_group) {
                    Some(additional_assets) => additional_assets,
                    None => return Ok(entry.clone()),
                };

                let should_save = additional_assets.remove_token_wallet(root_token_contract);
                (entry.clone(), should_save)
            }
            None => return Err(AccountsStorageError::AccountNotFound.into()),
        };

        if should_save {
            self.save(assets).await?;
        }
        Ok(entry)
    }

    /// Removes specified from the storage and resets current account if needed
    pub async fn remove_account(&self, account: &str) -> Result<Option<AssetsList>> {
        let assets = &mut *self.accounts.write().await;
        let result = assets.remove(account);

        self.save(assets).await?;
        Ok(result)
    }

    /// Removes all accounts and resets current account
    pub async fn clear(&self) -> Result<()> {
        self.storage.remove(STORAGE_ACCOUNTS).await?;

        let assets = &mut *self.accounts.write().await;
        assets.clear();

        self.storage.remove(STORAGE_ACCOUNTS).await
    }

    /// Returns handler to the inner data
    pub async fn stored_data(&'_ self) -> StoredAccountsData<'_> {
        StoredAccountsData(self.accounts.read().await)
    }

    async fn save(&self, assets: &AssetsMap) -> Result<()> {
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
        }

        let data = serde_json::to_string(&StoredData {
            assets: StoredAssetsMap(assets),
        })
        .trust_me();
        self.storage.set(STORAGE_ACCOUNTS, &data).await
    }
}

pub struct StoredAccountsData<'a>(RwLockReadGuard<'a, AssetsMap>);

impl<'a> StoredAccountsData<'a> {
    pub fn accounts(&self) -> &AssetsMap {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetsList {
    pub name: String,
    pub ton_wallet: TonWalletAsset,

    /// Additional assets, grouped by network group
    pub additional_assets: HashMap<String, AdditionalAssets>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdditionalAssets {
    pub token_wallets: Vec<TokenWalletAsset>,
    pub depools: Vec<DePoolAsset>,
}

impl AdditionalAssets {
    pub fn has_token_wallet(&self, root_token_contract: &MsgAddressInt) -> bool {
        self.token_wallets
            .iter()
            .any(|item| &item.root_token_contract == root_token_contract)
    }

    fn with_token_wallet(root_token_contract: MsgAddressInt) -> Self {
        Self {
            token_wallets: vec![TokenWalletAsset {
                root_token_contract,
            }],
            ..Default::default()
        }
    }

    fn add_token_wallet(&mut self, root_token_contract: MsgAddressInt) -> bool {
        if !self.has_token_wallet(&root_token_contract) {
            self.token_wallets.push(TokenWalletAsset {
                root_token_contract,
            });
            true
        } else {
            false
        }
    }

    fn remove_token_wallet(&mut self, root_token_contract: &MsgAddressInt) -> bool {
        let pos = self
            .token_wallets
            .iter()
            .position(|item| item.root_token_contract == *root_token_contract);

        if let Some(index) = pos {
            self.token_wallets.remove(index);
            true
        } else {
            false
        }
    }
}

impl<'de> serde::Deserialize<'de> for AssetsList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum ParsedAssetsList {
            Old {
                name: String,
                ton_wallet: TonWalletAsset,
                token_wallets: Vec<TokenWalletAsset>,
                depools: Vec<DePoolAsset>,
            },
            New {
                name: String,
                ton_wallet: TonWalletAsset,
                additional_assets: HashMap<String, AdditionalAssets>,
            },
        }

        Ok(match ParsedAssetsList::deserialize(deserializer)? {
            ParsedAssetsList::Old {
                name,
                ton_wallet,
                token_wallets,
                depools,
            } => {
                let mut additional_assets = HashMap::with_capacity(1);
                additional_assets.insert(
                    DEFAULT_NETWORK_GROUP.to_owned(),
                    AdditionalAssets {
                        token_wallets,
                        depools,
                    },
                );

                AssetsList {
                    name,
                    ton_wallet,
                    additional_assets,
                }
            }
            ParsedAssetsList::New {
                name,
                ton_wallet,
                additional_assets,
            } => AssetsList {
                name,
                ton_wallet,
                additional_assets,
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TonWalletAsset {
    #[serde(with = "serde_address")]
    pub address: MsgAddressInt,
    #[serde(with = "serde_public_key")]
    pub public_key: ed25519_dalek::PublicKey,
    pub contract: ton_wallet::ContractType,
    #[serde(with = "serde_public_key")]
    pub owners: ed25519_dalek::PublicKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenWalletAsset {
    #[serde(with = "serde_address")]
    pub root_token_contract: MsgAddressInt,
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
