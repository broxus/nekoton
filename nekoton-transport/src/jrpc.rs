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
    use nekoton::{
        abi::{
            num_bigint::BigUint, tvm::ExecutionError, BigUint256, BriefBlockchainConfig,
            BuildTokenValue, FunctionExt, TokenValueExt,
        },
        external::{JrpcConnection, JrpcRequest, JrpcResponse},
    };
    use nekoton_utils::{SimpleClock, TrustMe};
    use serde::Deserialize;
    use ton_types::{BuilderData, HashmapE};

    use super::*;

    #[tokio::test]
    #[ignore]
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

    #[tokio::test]
    #[ignore]
    async fn jrpc_client_works2() {
        let client = JrpcClient::new("https://rpc-testnet.tychoprotocol.com/").unwrap();

        const QUERY: &str = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getContractState",
            "params": {
                "address": "0:84105d39805e023053cbf2b6a30e3c495b41678eec854b0fa56c9228abd5c975"
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

    #[tokio::test]
    #[ignore]
    async fn get_state_with_retries_for_libraries_when_contract_code_is_library() {
        let client = JrpcClient::new("https://rpc-testnet.tychoprotocol.com/").unwrap();

        let contract = r#####"{
            "ABI version": 2,
            "version": "2.7",
            "header": ["pubkey", "time", "expire"],
            "functions": [
                {
                    "name": "balance",
                    "inputs": [
                        {"name":"answerId","type":"uint32"}
                    ],
                    "outputs": [
                        {"name":"value0","type":"uint128"}
                    ]
		        }
            ],
            "data": [],
            "events": []
        }"#####;

        let contract_abi = ton_abi::Contract::load(contract.as_bytes()).trust_me();
        let function = contract_abi.function("balance").trust_me();

        let bytes = base64::decode("te6ccgEBBAEA3wACboARPmKFmZb7UI1FgPY5MbJYJKPzmu4RUDN9k8WayPe7kGQRAqUGil+P0AAAT3BmG1o6AvrwgCYDAQGTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAIurEomVjZY/EfuvEyNXOvBmybt5bgpnmtwgyymLnInvgCAGOACOx2tye/5lfR4Ih+BBGfLQA67cTHekeUzHx9YuGo73UAAAAAAAAAAAAAAAAAAAABUAhCApZ8lwbZVdfn7LyATToKdb89MzDWfAhUcDRsBzsioiQS").unwrap();
        let stuff = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())
            .and_then(nekoton_utils::deserialize_account_stuff)
            .unwrap();

        let mut brief_blockchain_config = BriefBlockchainConfig::default();
        brief_blockchain_config.capabilities |= 0x0000_0000_0800;
        println!("{brief_blockchain_config:?}");

        let mut libraries = vec![];

        loop {
            let res = function.run_local_ext(
                &SimpleClock,
                stuff.clone(),
                &[0u32.token_value().named("answerId")],
                false,
                &brief_blockchain_config,
                &libraries,
            );

            match res {
                Err(err) => match err.downcast::<ExecutionError>() {
                    Ok(ExecutionError::MissingLibrary { hash }) => {
                        println!("Missing library: {hash}");

                        let query = serde_json::json!({
                                    "jsonrpc": "2.0","id": 1,"method": "getLibraryCell","params": {"hash": hash.to_hex_string()}} );

                        #[derive(Deserialize)]
                        struct LibraryCellResponse {
                            cell: Option<String>,
                        }

                        let response = client
                            .post(JrpcRequest {
                                data: query.to_string(),
                                requires_db: true,
                            })
                            .await
                            .unwrap();

                        let LibraryCellResponse { cell } =
                            match serde_json::from_str(&response).unwrap() {
                                JrpcResponse::Success(response) => response,
                                JrpcResponse::Err(err) => panic!("Error: {}", err),
                            };

                        if let Some(cell_s) = cell {
                            let bytes = base64::decode(cell_s).unwrap();
                            let c = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())
                                .unwrap();

                            let mut lib = HashmapE::with_bit_len(256);
                            let mut item = BuilderData::new();
                            item.checked_append_reference(c).unwrap();
                            lib.set_builder(hash.into(), &item).unwrap();
                            libraries.push(lib);
                        }
                    }
                    Ok(err) => {
                        println!("ok {err:?}");
                        break;
                    }
                    Err(err) => {
                        println!("err {err:?}");
                        break;
                    }
                },
                Ok(res) => {
                    println!("ok {res:?}");
                    break;
                }
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn get_state_with_retries_for_libraries_when_library_call_is_inside_contract() {
        let client = JrpcClient::new("https://rpc-testnet.tychoprotocol.com/").unwrap();

        let contract = r#####"{
            "ABI version": 2,
            "version": "2.7",
            "header": ["time", "expire"],
            "functions": [
                {
                    "name": "testAddGetter",
                    "inputs": [
                        {"name":"a","type":"uint256"},
                        {"name":"b","type":"uint256"}
                    ],
                    "outputs": [
                        {"name":"value0","type":"uint256"}
                    ]
                }
            ],
            "data": [],
            "events": []
        }"#####;

        let contract_abi = ton_abi::Contract::load(contract.as_bytes()).trust_me();
        let function = contract_abi.function("testAddGetter").trust_me();

        let bytes = base64::decode("te6ccgECGAEAAwwAAm6AEIILpzALwEYKeX5W1GHHiStoLPHdkKlh9K2SRRV6uS6kYQo4horspSAAAFC2X/KIKlloLwAmAwEBkb1NrLsMcFKYoHq5uXkbVJzUkOEiypI/caoqHm/AFDeIAAABmOrGPYaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMACCEICTunDKDBYzp1WMjhzkahaIKI373nqkQCMY/dQTQhEVEoBEv8A9KQT9LzyCwQCASASBQOe8n+J+Gkh2zzTAAGOFIMI1xgg+CjIzs7J+QBY+EL5EPKo3tM/AfhDIbnytCD4I4ED6KiCCBt3QKC58rT4Y9Mf+CNYufK50x8B9KQg9KHyPBEWBgIBSAwHAgEgCggCb7qtnHw/hG8uBM0//U0dDT/9HbPCGOHCPQ0wH6QDAxyM+HIM6CEOrZx8PPC4HL/8lw+wCRMOLbPICQ8AGPhK0O0eWYEdUFUC2AJvu0pKWt+Eby4EzT/9TR0NP/0ds8IY4cI9DTAfpAMDHIz4cgzoIQ1KSlrc8Lgcv/yXD7AJEw4ts8gLFAEkcPgA+ErQ7R5aiYEyhlUD2PhrEQIBIA4NAj+7yR4cX4Qm7jAPhG8nPT/9H4AMjPhArL/3/PI/hq2zyBYUAnu6WhFNz4RvLgTNP/1NHQ0//R2zwijiIk0NMB+kAwMcjPhyDOcc8LYQLIz5IWhFNyy//L/83JcPsAkVvi2zyBAPACjtRNDT/9M/MfhDWMjL/8s/zsntVAAc+AD4StDtHlmBP/5VAtgAQ4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABADZNJw7UTQgQFA1yHXCgD4ZiLQ0wP6QDD4aak4ANwhxwDjAiHXDR/yvCHjAwH0pCD0ofI8FxcTAyqgTOUUevhG8uBM2zzT/9P/0ds82zwWFRQAKvhL+Er4Q/hCyMv/yz/Pg8zL/8ntVAAyghCy0F4AcvsC+ErQ7R5Z+EmBMoZVA9j4awAu7UTQ0//TP9MA1NP/0fhr+Gr4Zvhj+GIACvhG8uBM").unwrap();

        let stuff = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())
            .and_then(nekoton_utils::deserialize_account_stuff)
            .unwrap();

        let mut brief_blockchain_config = BriefBlockchainConfig::default();
        brief_blockchain_config.capabilities |= 0x0000_0000_0800;
        println!("{brief_blockchain_config:?}");

        let mut libraries = vec![];

        loop {
            let res = function.run_local_ext(
                &SimpleClock,
                stuff.clone(),
                &[
                    BigUint256(BigUint::from(1u32))
                        .token_value()
                        .token_value()
                        .named("a"),
                    BigUint256(BigUint::from(1u32))
                        .token_value()
                        .token_value()
                        .named("b"),
                ],
                false,
                &brief_blockchain_config,
                &libraries,
            );

            match res {
                Err(err) => match err.downcast::<ExecutionError>() {
                    Ok(ExecutionError::MissingLibrary { hash }) => {
                        println!("Missing library: {hash}");

                        let query = serde_json::json!({
                                    "jsonrpc": "2.0","id": 1,"method": "getLibraryCell","params": {"hash": hash.to_hex_string()}} );

                        #[derive(Deserialize)]
                        struct LibraryCellResponse {
                            cell: Option<String>,
                        }

                        let response = client
                            .post(JrpcRequest {
                                data: query.to_string(),
                                requires_db: true,
                            })
                            .await
                            .unwrap();

                        let LibraryCellResponse { cell } =
                            match serde_json::from_str(&response).unwrap() {
                                JrpcResponse::Success(response) => response,
                                JrpcResponse::Err(err) => panic!("Error: {}", err),
                            };

                        if let Some(cell_s) = cell {
                            let bytes = base64::decode(cell_s).unwrap();
                            let c = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())
                                .unwrap();

                            let mut lib = HashmapE::with_bit_len(256);
                            let mut item = BuilderData::new();
                            item.checked_append_reference(c).unwrap();
                            lib.set_builder(hash.into(), &item).unwrap();
                            libraries.push(lib);
                        }
                    }
                    Ok(err) => {
                        println!("ok {err:?}");
                        break;
                    }
                    Err(err) => {
                        println!("err {err:?}");
                        break;
                    }
                },
                Ok(res) => {
                    println!("ok {res:?}");
                    break;
                }
            }
        }
    }
}
