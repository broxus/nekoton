use std::convert::TryInto;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use nekoton_utils::*;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tokio::sync::futures::Notified;
use tokio::sync::Notify;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlNetworkSettings {
    /// Path to graphql api endpoints, e.g. `https://main.ton.dev`
    pub endpoints: Vec<String>,
    /// Frequency of sync latency detection. Default: `60000`
    #[serde(with = "serde_duration_ms")]
    pub latency_detection_interval: Duration,
    /// Maximum value for the endpoint's blockchain data sync latency. Default: `60000`
    #[serde(with = "serde_duration_ms")]
    pub max_latency: Duration,
    /// Maximum amount of retries during endpoint selection
    pub endpoint_selection_retry_count: usize,
    /// Gql node type
    pub local: bool,
}

impl Default for GqlNetworkSettings {
    fn default() -> Self {
        Self {
            endpoints: Vec::new(),
            latency_detection_interval: Duration::from_secs(60),
            max_latency: Duration::from_secs(60),
            endpoint_selection_retry_count: 5,
            local: false,
        }
    }
}

pub struct GqlClient {
    client: reqwest::Client,
    endpoints: Vec<Endpoint>,
    latency_detection_interval: u64,
    max_latency: u32,
    endpoint_selection_retry_count: usize,
    local: bool,
    flags: AtomicU64,
    notify: Notify,
}

impl GqlClient {
    pub fn new(settings: GqlNetworkSettings) -> Result<Arc<Self>> {
        let endpoints = settings
            .endpoints
            .into_iter()
            .map(|endpoint| {
                Endpoint::new(&endpoint)
                    .with_context(|| format!("failed to parse endpoint: {}", endpoint))
            })
            .collect::<Result<Vec<_>>>()?;
        if endpoints.is_empty() {
            return Err(GqlClientError::NoEndpointsSpecified.into());
        }

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );

        let client = reqwest::ClientBuilder::new()
            .default_headers(headers)
            .build()
            .context("failed to build http client")?;

        Ok(Arc::new(Self {
            client,
            endpoints,
            latency_detection_interval: settings.latency_detection_interval.as_secs(),
            max_latency: settings.max_latency.as_millis() as u32,
            endpoint_selection_retry_count: settings.endpoint_selection_retry_count,
            local: settings.local,
            flags: Default::default(),
            notify: Default::default(),
        }))
    }

    async fn select_querying_endpoint(&self) -> Result<&'_ Endpoint> {
        // Low 4 bytes which are used as endpoint index
        const INDEX_MASK: u64 = 0x0000_0000_ffff_ffff;

        const INTERMEDIATE: u64 = 0x0000_0000_ffff_fffe;
        const IN_PROCESS: u64 = 0x0000_0000_ffff_ffff;

        struct Guard<'a> {
            client: &'a GqlClient,
            result: Option<u64>,
        }

        impl<'a> Guard<'a> {
            fn new(client: &'a GqlClient) -> Self {
                Self {
                    client,
                    result: None,
                }
            }

            fn set_result(&mut self, index: usize) {
                self.result = Some((index as u64) & INDEX_MASK);
            }
        }

        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                let state = match self.result {
                    Some(result) => {
                        let detection_time = now_sec_u64() + self.client.latency_detection_interval;
                        (detection_time << 32) | result
                    }
                    None => 0,
                };

                // Lock the loop
                self.client.flags.store(INTERMEDIATE, Ordering::Release);
                // Notify all `notify_fut`
                self.client.notify.notify_waiters();
                // Update state
                self.client.flags.store(state, Ordering::Release);
            }
        }

        let now = now_sec_u64();

        let mut notify_fut: Option<Notified<'_>> = None;
        loop {
            let state = self.flags.load(Ordering::Acquire);
            match state >> 32 {
                // Not detecting yet
                detection_time if now < detection_time => {
                    break self
                        .endpoints
                        .get((state & INDEX_MASK) as usize)
                        .ok_or_else(|| GqlClientError::EndpointNotFound.into())
                }

                // Waiting flags change
                INTERMEDIATE => continue,

                // Already searching endpoint
                IN_PROCESS => match notify_fut.take() {
                    Some(notify_fut) => notify_fut.await,
                    None => notify_fut = Some(self.notify.notified()),
                },

                _ => {
                    match self.flags.compare_exchange(
                        state,
                        IN_PROCESS,
                        Ordering::Release,
                        Ordering::Relaxed,
                    ) {
                        // Start searching best endpoint
                        Ok(_) => {
                            // This guard will reset the state back in case of error
                            // or unlock other waiters on success
                            let mut guard = Guard::new(self);

                            let (index, endpoint) = self.find_best_endpoint().await?;
                            guard.set_result(index);

                            break Ok(endpoint);
                        }
                        // State has already been changed
                        Err(_) => continue,
                    }
                }
            }
        }
    }

    async fn find_best_endpoint(&'_ self) -> Result<(usize, &'_ Endpoint)> {
        for i in 1..=self.endpoint_selection_retry_count {
            let mut requests = FuturesUnordered::new();

            for (i, endpoint) in self.endpoints.iter().enumerate() {
                requests.push(async move { (i, endpoint, self.check_latency(endpoint).await) });
            }

            let mut last_latency = None;
            while let Some((i, endpoint, response)) = requests.next().await {
                match response {
                    Ok(latency) if latency <= self.max_latency => return Ok((i, endpoint)),
                    Ok(latency) => {
                        if matches!(&last_latency, Some((_, _, Some(l))) if latency < *l) {
                            last_latency = Some((i, endpoint, Some(latency)))
                        }
                    }
                    Err(e) => {
                        log::debug!("GQL endpoint selection error: {:?}", e);
                    }
                }
            }

            if let Some((i, endpoint, _)) = last_latency {
                return Ok((i, endpoint));
            }

            let interval = std::cmp::min(i * 100, 5000);
            tokio::time::sleep(Duration::from_millis(interval as u64)).await;
        }

        Err(GqlClientError::NoEndpointFound.into())
    }

    async fn check_latency(&self, endpoint: &Endpoint) -> Result<u32> {
        #[derive(Deserialize)]
        struct GqlResponse {
            data: GqlResponseData,
        }

        #[derive(Deserialize)]
        struct GqlResponseData {
            info: GqlResponseInfo,
        }

        #[derive(Deserialize)]
        struct GqlResponseInfo {
            latency: u32,
        }

        let response = self.client.get(endpoint.status.clone()).send().await?;
        let response: GqlResponse = response.json().await?;
        Ok(response.data.info.latency)
    }
}

#[async_trait::async_trait]
impl nekoton::external::GqlConnection for GqlClient {
    fn is_local(&self) -> bool {
        self.local
    }

    async fn post(&self, req: nekoton::external::GqlRequest) -> Result<String> {
        let endpoint = self.select_querying_endpoint().await?;
        let response = self
            .client
            .post(endpoint.gql.clone())
            .body(req.data)
            .send()
            .await?;
        Ok(response.text().await?)
    }
}

struct Endpoint {
    gql: Url,
    status: Url,
}

impl Endpoint {
    fn new(url: &str) -> Result<Self> {
        let gql = expand_address(url);
        let status = format!("{}?query=%7Binfo%7Bversion%20time%20latency%7D%7D", gql);
        Ok(Self {
            gql: gql.as_str().try_into()?,
            status: status.as_str().try_into()?,
        })
    }
}

fn expand_address(base_url: &str) -> String {
    match base_url.trim_end_matches('/') {
        url if base_url.starts_with("http://") || base_url.starts_with("https://") => {
            format!("{}/graphql", url)
        }
        url @ ("localhost" | "127.0.0.1") => format!("http://{}/graphql", url),
        url => format!("https://{}/graphql", url),
    }
}

#[derive(thiserror::Error, Debug)]
enum GqlClientError {
    #[error("no endpoints specified")]
    NoEndpointsSpecified,
    #[error("no valid GQL endpoint found")]
    NoEndpointFound,
    #[error("endpoint not found")]
    EndpointNotFound,
}

#[cfg(test)]
mod tests {
    use nekoton::external::{GqlConnection, GqlRequest};

    use super::*;

    #[tokio::test]
    async fn gql_client_works() {
        let client = GqlClient::new(GqlNetworkSettings {
            endpoints: vec!["mainnet.evercloud.dev/57a5b802e303424fb0078f612a4fbe35".to_string()],
            latency_detection_interval: Duration::from_secs(1),
            ..Default::default()
        })
        .unwrap();

        const QUERY: &str = r#"{
            "query": "query { accounts { id } }"
        }"#;

        let response = client
            .post(GqlRequest {
                data: QUERY.to_string(),
                long_query: false,
            })
            .await
            .unwrap();
        println!("{}", response);
    }
}
