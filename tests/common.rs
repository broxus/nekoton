use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Error, Result};
use async_trait::async_trait;
use tokio::sync::Mutex;

use nekoton::external::{GqlConnection, Storage};
use reqwest::Url;

#[derive(Default, Debug)]
pub struct StorageImpl {
    inner: Arc<Mutex<HashMap<String, String>>>,
}
impl StorageImpl {
    pub fn new() -> Self {
        Default::default()
    }
}
#[async_trait]
impl Storage for StorageImpl {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.inner.lock().await.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str) -> Result<()> {
        self.inner.lock().await.insert(key.into(), value.into());
        Ok(())
    }

    fn set_unchecked(&self, key: &str, value: &str) {
        let inner = self.inner.clone();
        let key = key.to_string();
        let value = value.to_string();
        tokio::spawn(async move {
            inner.lock().await.insert(key, value);
        });
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.inner.lock().await.remove(key);
        Ok(())
    }

    fn remove_unchecked(&self, key: &str) {
        let inner = self.inner.clone();
        let key = key.to_string();
        tokio::spawn(async move {
            inner.lock().await.remove(&key);
        });
    }
}

#[derive(Default)]
pub struct GqlImpl {
    client: reqwest::Client,
}

#[async_trait::async_trait]
impl GqlConnection for GqlImpl {
    async fn post(&self, data: &str) -> Result<String> {
        let data = data.to_string();
        let req = self
            .client
            .post("https://main.ton.dev/graphql".parse::<Url>().unwrap())
            .body(data)
            .build()?;
        self.client
            .execute(req)
            .await?
            .text()
            .await
            .map_err(|e| Error::new(e))
    }
}

pub fn create_storage() -> StorageImpl {
    StorageImpl::new()
}
