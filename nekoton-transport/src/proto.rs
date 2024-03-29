use std::sync::Arc;

use anyhow::{Context, Result};
use nekoton_proto::prost::Message;
use nekoton_proto::protos::rpc;
use reqwest::{IntoUrl, StatusCode, Url};

pub struct ProtoClient {
    client: reqwest::Client,
    base_url: Url,
    alternative_url: Option<Url>,
}

impl ProtoClient {
    pub fn new<U: IntoUrl>(endpoint: U) -> Result<Arc<Self>> {
        let url = endpoint.into_url()?;

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/x-protobuf"),
        );

        let client = reqwest::ClientBuilder::new()
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
impl nekoton::external::ProtoConnection for ProtoClient {
    async fn post(&self, req: nekoton::external::ProtoRequest) -> Result<Vec<u8>> {
        let url = if req.requires_db {
            self.alternative_url.as_ref().unwrap_or(&self.base_url)
        } else {
            &self.base_url
        };

        let response = self.client.post(url.clone()).body(req.data).send().await?;

        let res = match response.status() {
            StatusCode::OK => response.bytes().await?.into(),
            StatusCode::UNPROCESSABLE_ENTITY => {
                let msg = rpc::Error::decode(response.bytes().await?)?;
                anyhow::bail!(msg.message)
            }
            _ => anyhow::bail!(response.status().to_string()),
        };

        Ok(res)
    }
}
