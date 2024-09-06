use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::{IntoUrl, Url};

pub struct JrpcClient {
    client: reqwest::Client,
    base_url: Url,
    alternative_url: Option<Url>,
}

impl JrpcClient {
    pub fn new<U: IntoUrl>(endpoint: U) -> Result<Arc<Self>> {
        let url = endpoint.into_url()?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );

        let client = reqwest::ClientBuilder::new()
            .http2_prior_knowledge()
            .default_headers(headers)
            .build()
            .context("failed to build http client")?;

        Ok(Arc::new(Self {
            client,
            base_url: url,
            alternative_url: None,
        }))
    }

    /// Set an alternative URL which will be used for requests that don't require a db
    pub fn set_alternative_url<U: IntoUrl>(&mut self, endpoint: U) -> Result<()> {
        self.alternative_url = Some(endpoint.into_url()?);
        Ok(())
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
impl nekoton::external::JrpcConnection for JrpcClient {
    async fn post(&self, req: nekoton::external::JrpcRequest) -> Result<String> {
        let url = if req.requires_db {
            self.alternative_url.as_ref().unwrap_or(&self.base_url)
        } else {
            &self.base_url
        };
        let response = self.client.post(url.clone()).body(req.data).send().await?;
        Ok(response.text().await?)
    }
}

#[cfg(test)]
mod tests {
    use nekoton::external::{JrpcConnection, JrpcRequest};

    use super::*;

    #[tokio::test]
    async fn jrpc_client_works() {
        let client = JrpcClient::new("https://jrpc.everwallet.net/rpc").unwrap();

        const QUERY: &str = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": {
                "id": "4a0a06bfbfaba4da8fcc7f5ad617fdee5344d954a1794e35618df2a4b349d15c"
            }
        }"#;

        let response = client
            .post(JrpcRequest {
                data: QUERY.to_owned(),
                requires_db: true,
            })
            .await
            .unwrap();
        println!("{}", response);
    }
}
