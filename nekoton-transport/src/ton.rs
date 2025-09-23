use reqwest::{IntoUrl, Url};
use serde::Serialize;

pub struct TonClient {
    endpoint: Url,
    client: reqwest::Client,
}

impl TonClient {
    pub fn new_v4<U: IntoUrl>(endpoint: U) -> anyhow::Result<Self> {
        let url = endpoint.into_url()?;
        Ok(Self {
            endpoint: url,
            client: reqwest::Client::new(),
        })
    }

    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub async fn send_get<U: IntoUrl>(&self, path: U) -> anyhow::Result<Option<String>> {
        let path = path.into_url()?;
        let result = self
            .client
            .get(self.endpoint.clone().join(path.as_str())?)
            .header("ContentType", "application/json")
            .send()
            .await?;

        if matches!(result.status(), reqwest::StatusCode::NOT_FOUND) {
            return Ok(None);
        }

        let result = result.text().await?;
        Ok(Some(result))
    }

    pub async fn send_post<R: Serialize, U: IntoUrl>(
        &self,
        body: R,
        path: U,
    ) -> anyhow::Result<Option<String>> {
        let path = path.into_url()?;
        let result = self
            .client
            .post(self.endpoint.clone().join(path.as_str())?)
            .body(serde_json::to_string(&body)?)
            .header("ContentType", "application/json")
            .send()
            .await?;

        if matches!(result.status(), reqwest::StatusCode::NOT_FOUND) {
            return Ok(None);
        }

        let result = result.text().await?;
        Ok(Some(result))
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
impl nekoton::external::TonConnection for TonClient {
    async fn send_get(&self, path: &str) -> anyhow::Result<Option<String>> {
        self.send_get(path).await
    }

    async fn send_post(&self, body: &str, path: &str) -> anyhow::Result<Option<String>> {
        self.send_post(body, path).await
    }
}
