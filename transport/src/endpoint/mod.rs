use std::sync::Arc;

use everscale_types::cell::DynCell;
use everscale_types::models::StdAddr;
use nekoton_core::transport::{ContractState, Transport};
use reqwest::Url;

use crate::models::Timings;
use crate::LiveCheckResult;

mod jrpc;

#[derive(Clone)]
pub struct Endpoint {
    inner: Arc<dyn Connection>,
}

impl Endpoint {
    pub fn new(endpoint: Url, client: reqwest::Client) -> Self {
        let is_jrpc = endpoint.path().ends_with("/rpc");
        let client = if is_jrpc {
            jrpc::JrpcClient::new(endpoint, client)
        } else {
            // Proto implementation
            todo!()
        };

        Self {
            inner: Arc::new(client),
        }
    }
}

impl Eq for Endpoint {}

impl PartialEq<Self> for Endpoint {
    fn eq(&self, other: &Self) -> bool {
        self.inner.endpoint() == other.inner.endpoint()
    }
}

impl PartialOrd<Self> for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.eq(other) {
            std::cmp::Ordering::Equal
        } else {
            let left_stats = self.inner.get_stats();
            let right_stats = other.inner.get_stats();

            match (left_stats, right_stats) {
                (Some(left_stats), Some(right_stats)) => left_stats.cmp(&right_stats),
                (None, Some(_)) => std::cmp::Ordering::Less,
                (Some(_), None) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        }
    }
}

#[async_trait::async_trait]
impl Transport for Endpoint {
    async fn broadcast_message(&self, message: &DynCell) -> anyhow::Result<()> {
        self.inner.broadcast_message(message).await
    }

    async fn get_contract_state(&self, address: &StdAddr) -> anyhow::Result<ContractState> {
        self.inner.get_contract_state(address).await
    }
}

#[async_trait::async_trait]
pub trait Connection: Transport + Send + Sync {
    async fn is_alive(&self) -> bool {
        let check_result = self.is_alive_inner().await;
        let is_alive = check_result.as_bool();
        self.update_was_dead(!is_alive);

        match check_result {
            LiveCheckResult::Live(stats) => self.set_stats(Some(stats)),
            LiveCheckResult::Dead => {}
        }

        is_alive
    }

    fn endpoint(&self) -> &str;

    fn get_stats(&self) -> Option<Timings>;

    fn set_stats(&self, stats: Option<Timings>);

    fn update_was_dead(&self, is_dead: bool);

    async fn is_alive_inner(&self) -> LiveCheckResult;
}

#[async_trait::async_trait]
impl Connection for Endpoint {
    async fn is_alive(&self) -> bool {
        self.inner.is_alive().await
    }

    fn endpoint(&self) -> &str {
        self.inner.endpoint()
    }

    fn get_stats(&self) -> Option<Timings> {
        self.inner.get_stats()
    }

    fn set_stats(&self, stats: Option<Timings>) {
        self.inner.set_stats(stats)
    }

    fn update_was_dead(&self, is_dead: bool) {
        self.inner.update_was_dead(is_dead)
    }

    async fn is_alive_inner(&self) -> LiveCheckResult {
        self.inner.is_alive_inner().await
    }
}
