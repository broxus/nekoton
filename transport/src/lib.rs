use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use everscale_types::cell::DynCell;
use everscale_types::models::StdAddr;
use futures_util::StreamExt;
use nekoton_core::transport::{ContractState, Transport};
use parking_lot::RwLock;
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::endpoint::{Connection, Endpoint};
use crate::models::Timings;

mod endpoint;
mod models;
mod utils;

static ROUND_ROBIN_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
pub struct RpcClient {
    inner: Arc<Inner>,
}

pub struct Inner {
    endpoints: Vec<Endpoint>,
    live_endpoints: RwLock<Vec<Endpoint>>,
    options: ClientOptions,
}

impl RpcClient {
    async fn new<I: IntoIterator<Item = Url> + Send>(
        endpoints: I,
        options: ClientOptions,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(options.request_timeout)
            .tcp_keepalive(Duration::from_secs(60))
            .http2_adaptive_window(true)
            .http2_keep_alive_interval(Duration::from_secs(60))
            .http2_keep_alive_timeout(Duration::from_secs(1))
            .http2_keep_alive_while_idle(true)
            .gzip(false)
            .build()?;

        let endpoints = endpoints
            .into_iter()
            .map(|endpoint| Endpoint::new(endpoint, client.clone()))
            .collect();

        let transport = Self {
            inner: Arc::new(Inner {
                endpoints,
                options,
                live_endpoints: Default::default(),
            }),
        };

        let mut live = transport.update_endpoints().await;

        if live == 0 {
            anyhow::bail!("No live endpoints");
        }

        let gt = transport.clone();
        tokio::spawn(async move {
            loop {
                let sleep_time = if live != 0 {
                    gt.inner.options.probe_interval
                } else {
                    gt.inner.options.aggressive_poll_interval
                };

                tokio::time::sleep(sleep_time).await;
                live = gt.update_endpoints().await;
            }
        });

        Ok(transport)
    }

    async fn get_client(&self) -> Option<Endpoint> {
        for _ in 0..self.inner.endpoints.len() {
            let client = {
                let live_endpoints = self.inner.live_endpoints.read();
                self.inner.options.choose_strategy.choose(&live_endpoints)
            };

            if client.is_some() {
                return client;
            } else {
                tokio::time::sleep(self.inner.options.aggressive_poll_interval).await;
            }
        }

        None
    }

    async fn with_retries<F, Fut, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: Fn(Endpoint) -> Fut,
        Fut: Future<Output = anyhow::Result<T>>,
    {
        const NUM_RETRIES: usize = 10;

        for tries in 0..NUM_RETRIES {
            let client = self
                .get_client()
                .await
                .ok_or(TransportError::NoEndpointsAvailable)?;

            // TODO: lifetimes to avoid of cloning?
            match f(client.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if tries == NUM_RETRIES - 1 {
                        return Err(e);
                    }

                    self.remove_endpoint(client.endpoint());

                    tokio::time::sleep(self.inner.options.aggressive_poll_interval).await;
                }
            }
        }

        unreachable!()
    }

    async fn update_endpoints(&self) -> usize {
        let mut futures = futures_util::stream::FuturesUnordered::new();
        for endpoint in &self.inner.endpoints {
            futures.push(async move { endpoint.is_alive().await.then(|| endpoint.clone()) });
        }

        let mut new_endpoints = Vec::with_capacity(self.inner.endpoints.len());
        while let Some(endpoint) = futures.next().await {
            new_endpoints.extend(endpoint);
        }

        let mut old_endpoints = self.inner.live_endpoints.write();

        *old_endpoints = new_endpoints;
        old_endpoints.len()
    }

    fn remove_endpoint(&self, endpoint: &str) {
        self.inner
            .live_endpoints
            .write()
            .retain(|c| c.endpoint() != endpoint);
    }
}

#[async_trait::async_trait]
impl Transport for RpcClient {
    // TODO: avoid of additional Future created by async move { ... }

    async fn broadcast_message(&self, message: &DynCell) -> anyhow::Result<()> {
        self.with_retries(|client| async move { client.broadcast_message(message).await })
            .await
    }

    async fn get_contract_state(&self, address: &StdAddr) -> anyhow::Result<ContractState> {
        self.with_retries(|client| async move { client.get_contract_state(address).await })
            .await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientOptions {
    /// How often the probe should update health statuses.
    ///
    /// Default: `1 sec`
    pub probe_interval: Duration,

    /// How long to wait for a response from a node.
    ///
    /// Default: `1 sec`
    pub request_timeout: Duration,

    /// How long to wait between health checks in case if all nodes are down.
    ///
    /// Default: `1 sec`
    pub aggressive_poll_interval: Duration,

    /// Rotation Strategy.
    ///
    /// Default: `Random`
    pub choose_strategy: ChooseStrategy,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(1),
            request_timeout: Duration::from_secs(3),
            aggressive_poll_interval: Duration::from_secs(1),
            choose_strategy: ChooseStrategy::Random,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub enum ChooseStrategy {
    Random,
    RoundRobin,
    /// Choose the endpoint with the lowest latency
    TimeBased,
}

impl ChooseStrategy {
    fn choose(&self, endpoints: &[Endpoint]) -> Option<Endpoint> {
        use rand::prelude::SliceRandom;

        match self {
            ChooseStrategy::Random => endpoints.choose(&mut rand::thread_rng()).cloned(),
            ChooseStrategy::RoundRobin => {
                let index = ROUND_ROBIN_COUNTER.fetch_add(1, Ordering::Release);
                endpoints.get(index % endpoints.len()).cloned()
            }
            ChooseStrategy::TimeBased => endpoints
                .iter()
                .min_by(|&left, &right| left.cmp(right))
                .cloned(),
        }
    }
}

pub enum LiveCheckResult {
    /// GetTimings request was successful
    Live(Timings),
    Dead,
}

impl LiveCheckResult {
    fn as_bool(&self) -> bool {
        match self {
            LiveCheckResult::Live(metrics) => metrics.is_reliable(),
            LiveCheckResult::Dead => false,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("No endpoint available")]
    NoEndpointsAvailable,
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use anyhow::Result;

    use super::*;

    #[tokio::test]
    async fn connection_test() -> Result<()> {
        let endpoints = ["http://57.129.53.62:8080/rpc"]
            .iter()
            .map(|x| x.parse().unwrap())
            .collect::<Vec<_>>();

        let _client = RpcClient::new(
            endpoints,
            ClientOptions {
                probe_interval: Duration::from_secs(10),
                ..Default::default()
            },
        )
        .await?;

        Ok(())
    }
}
