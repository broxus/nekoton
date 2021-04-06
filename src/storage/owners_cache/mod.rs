use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;
use tokio::sync::RwLock;
use ton_block::MsgAddressInt;

use crate::external::Storage;
use crate::utils::{NoFailure, TrustMe};

const STORAGE_OWNERS_CACHE: &str = "owners_cache";

/// Stores a map to resolve owner's wallet address from token wallet address
pub struct OwnersCache {
    storage: Arc<dyn Storage>,
    owners: RwLock<HashMap<MsgAddressInt, MsgAddressInt>>,
}

impl OwnersCache {
    pub async fn load(storage: Arc<dyn Storage>) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct OwnersMap(Vec<OwnersMapItem>);
        #[derive(Deserialize)]
        struct OwnersMapItem(String, String);

        let data = match storage.get(STORAGE_OWNERS_CACHE).await? {
            Some(data) => serde_json::from_str::<OwnersMap>(&data)?.0,
            None => Default::default(),
        }
        .into_iter()
        .map(|OwnersMapItem(token_wallet, owner_wallet)| {
            let token_wallet = MsgAddressInt::from_str(&token_wallet).convert()?;
            let owner_wallet = MsgAddressInt::from_str(&owner_wallet).convert()?;
            Result::<_, anyhow::Error>::Ok((token_wallet, owner_wallet))
        })
        .collect::<Result<HashMap<_, _>, _>>()?;

        Ok(Self {
            storage,
            owners: RwLock::new(data),
        })
    }

    pub async fn load_unchecked(storage: Arc<dyn Storage>) -> Self {
        Self::load(storage.clone()).await.unwrap_or_else(|_| Self {
            storage,
            owners: Default::default(),
        })
    }

    pub async fn get_owner(&self, token_wallet: &MsgAddressInt) -> Option<MsgAddressInt> {
        self.owners.read().await.get(token_wallet).cloned()
    }

    pub async fn add_owner(&self, token_wallet: MsgAddressInt, owner_wallet: MsgAddressInt) {
        let mut owners = self.owners.write().await;
        owners.insert(token_wallet, owner_wallet);
        self.save(&owners);
    }

    pub async fn add_owners_list<I>(&self, new_owners: I)
    where
        I: Iterator<Item = (MsgAddressInt, MsgAddressInt)>,
    {
        let mut owners = self.owners.write().await;
        owners.extend(new_owners);
        self.save(&*owners);
    }

    fn save(&self, owners: &HashMap<MsgAddressInt, MsgAddressInt>) {
        struct OwnersMap<'a>(&'a HashMap<MsgAddressInt, MsgAddressInt>);
        struct OwnersMapItem<'a>(&'a MsgAddressInt, &'a MsgAddressInt);

        impl<'a> serde::Serialize for OwnersMapItem<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeTuple;

                let mut tuple = serializer.serialize_tuple(2)?;
                tuple.serialize_element(&self.0.to_string())?;
                tuple.serialize_element(&self.1.to_string())?;
                tuple.end()
            }
        }

        impl<'a> serde::Serialize for OwnersMap<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                for (token_wallet, owner_wallet) in self.0.iter() {
                    seq.serialize_element(&OwnersMapItem(token_wallet, owner_wallet))?;
                }
                seq.end()
            }
        }

        let data = serde_json::to_string(&OwnersMap(owners)).trust_me();
        self.storage.set_unchecked(STORAGE_OWNERS_CACHE, &data);
    }
}
