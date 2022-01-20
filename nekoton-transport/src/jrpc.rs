use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::{IntoUrl, Url};

pub struct JrpcClient {
    client: reqwest::Client,
    url: Url,
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
            .default_headers(headers)
            .build()
            .context("failed to build http client")?;

        Ok(Arc::new(Self { client, url }))
    }
}

#[async_trait::async_trait]
impl nekoton::external::JrpcConnection for JrpcClient {
    async fn post(&self, data: &str) -> Result<String> {
        let response = self
            .client
            .post(self.url.clone())
            .body(data.to_owned())
            .send()
            .await?;
        Ok(response.text().await?)
    }
}

#[cfg(test)]
mod tests {
    use nekoton::external::JrpcConnection;

    use super::*;

    #[tokio::test]
    async fn jrpc_client_works() {
        let client = JrpcClient::new("https://extension-api.broxus.com/rpc").unwrap();

        const QUERY: &str = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": {
                "id": "4a0a06bfbfaba4da8fcc7f5ad617fdee5344d954a1794e35618df2a4b349d15c"
            }
        }"#;

        let response = client.post(QUERY).await.unwrap();
        println!("{}", response);
    }
}
