use std::convert::TryInto;
use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlExtNetworkSettings {
    pub endpoint: String,
    /// Gql node type
    pub local: bool,
}

pub struct GqlExtClient {
    client: reqwest::Client,
    endpoint: Endpoint,
    local: bool,
}

impl GqlExtClient {
    pub fn new(settings: GqlExtNetworkSettings) -> Result<Arc<Self>> {
        let endpoint = &settings.endpoint;
        let endpoint = Endpoint::new(endpoint)
            .with_context(|| format!("failed to parse endpoint: {}", endpoint))?;

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
            endpoint,
            local: settings.local,
        }))
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
impl nekoton::external::GqlConnection for GqlExtClient {
    fn is_local(&self) -> bool {
        self.local
    }

    async fn post(&self, req: nekoton::external::GqlRequest) -> Result<String> {
        let response = self
            .client
            .post(self.endpoint.gql.clone())
            .body(req.data)
            .send()
            .await?;
        Ok(response.text().await?)
    }
}

struct Endpoint {
    gql: Url,
}

impl Endpoint {
    fn new(url: &str) -> Result<Self> {
        let gql = expand_address(url);
        Ok(Self {
            gql: gql.as_str().try_into()?,
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

#[cfg(test)]
mod tests {
    use nekoton::abi::num_traits::ToPrimitive;
    use nekoton::abi::ExecutionContext;
    use nekoton::contracts::jetton;
    use nekoton::core::utils::update_library_cell;
    use nekoton::external::{GqlConnection, GqlRequest};
    use nekoton_utils::*;

    use super::*;

    #[tokio::test]
    async fn gql_client_works() -> Result<()> {
        let client = GqlExtClient::new(GqlExtNetworkSettings {
            endpoint: "https://dton.io/graphql".to_string(),
            local: false,
        })?;

        const QUERY: &str = r#"{"query":"{\n  get_lib(\n    lib_hash: \"0F1AD3D8A46BD283321DDE639195FB72602E9B31B1727FECC25E2EDC10966DF4\"\n  )\n}"}"#;

        let _response = client
            .post(GqlRequest {
                data: QUERY.to_string(),
                long_query: false,
            })
            .await?;

        Ok(())
    }

    #[tokio::test]
    async fn usdt_wallet_token_contract() -> Result<()> {
        let client = GqlExtClient::new(GqlExtNetworkSettings {
            endpoint: "https://dton.io/graphql".to_string(),
            local: false,
        })?;

        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgEBAwEAqAACbIAXsqVXAuRG6+GFp/25WVl2IsmatSkX0jbrXVjoBOwsnEQNAdiGdFv5kAABdRDp2cQZrn10JgIBAJEFJFfQYxaABHulQdJwYfnHP5r0FXhq3wjit36+D+zzx7bkE76OQgrwAsROplLUCShZxn2kTkyjrdZWWw4ol9ZAosUb+zcNiHf6CEICj0Utek39dAZraCNlF3JZ7QVzRDW+drX9S9XYryt8PWg=").unwrap().as_slice()).unwrap();
        let mut state = deserialize_account_stuff(cell)?;

        update_library_cell(client.as_ref(), &mut state.storage.state).await?;

        let contract = jetton::TokenWalletContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let balance = contract.balance()?;
        assert_eq!(balance.to_u128().unwrap(), 156092097302);

        Ok(())
    }

    #[tokio::test]
    async fn notcoin_wallet_token_contract() -> Result<()> {
        let client = GqlExtClient::new(GqlExtNetworkSettings {
            endpoint: "https://dton.io/graphql".to_string(),
            local: false,
        })?;

        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgEBAwEAqgACbIAX5XxfY9N6rJiyOS4NGQc01nd0dzEnWBk87cdqg9bLTwQNAeCGdH/3UAABdXbIjToZrn5eJgIBAJUHFxcOBj4fBYAfGfo6PQWliRZGmmqpYpA1QxmYkyLZonLf41f59x68XdAAvlWFDxGF2lXm67y4yzC17wYKD9A0guwPkMs1gOsM//IIQgK6KRjIlH6bJa+awbiDNXdUFz5YEvgHo9bmQqFHCVlTlQ==").unwrap().as_slice()).unwrap();
        let mut state = deserialize_account_stuff(cell)?;

        update_library_cell(client.as_ref(), &mut state.storage.state).await?;

        let contract = jetton::TokenWalletContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let balance = contract.balance()?;
        assert_eq!(balance.to_u128().unwrap(), 6499273466060549);

        Ok(())
    }

    #[tokio::test]
    async fn mintless_points_token_wallet_contract() -> Result<()> {
        let client = GqlExtClient::new(GqlExtNetworkSettings {
            endpoint: "https://dton.io/graphql".to_string(),
            local: false,
        })?;

        let cell =
            ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgEBAwEAyQACbIAMC6d7f4iHKlXHXBfufxF6w/5pIENHdpy1yJnyM+lsrQQNAl2Gc+Ll0AABc7gAAbghs2ElpgIBANQFAlQL5ACADZRqTnEksRaYvpXRMbgzB92SzFv/19WbfQQgdDo7lYwQA+mfQx3OTMfvDyPCOAYxl9HdjYWqWkQCtdgoLLcHjaDKvtRVlwuLLP8LwzhcDJNm1TPewFBFqmlIYet7ln0NupwfCEICDvGeG/QPK6SS/KrDhu7KWb9oJ6OFBwjZ/NmttoOrwzY=").unwrap().as_slice())
                .unwrap();
        let mut state = deserialize_account_stuff(cell)?;

        update_library_cell(client.as_ref(), &mut state.storage.state).await?;

        let contract = jetton::TokenWalletContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let data = contract.get_details()?;
        assert_eq!(data.balance.to_u128().unwrap(), 10000000000);

        Ok(())
    }

    #[tokio::test]
    async fn hamster_token_wallet_contract() -> Result<()> {
        let client = GqlExtClient::new(GqlExtNetworkSettings {
            endpoint: "https://dton.io/graphql".to_string(),
            local: false,
        })?;

        let cell =
            ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgEBAwEAyQACbIAKqccjBo+00V2Pb7qZhRYSHX52cx1iP9tpON3cdZrkP8QNAl2GdhkS0AABegbul1whs2ElpgIBANQFGHJ82gCACGZPh6infgRlai2q2zEzj6/XTCUYYz5sBXNuHUXFkiawACfLlnexAarJqUlmkXX/yPvEfPlx8Id4LDSocvlK3az1CNK1yFN5P0+WKSDutZY4tqmGqAE7w+lQchEcy4oOjEQUCEICDxrT2KRr0oMyHd5jkZX7cmAumzGxcn/swl4u3BCWbfQ=").unwrap().as_slice())
                .unwrap();
        let mut state = deserialize_account_stuff(cell)?;

        update_library_cell(client.as_ref(), &mut state.storage.state).await?;

        let contract = jetton::TokenWalletContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let data = contract.get_details()?;
        assert_eq!(data.balance.to_u128().unwrap(), 105000000000);

        Ok(())
    }
}
