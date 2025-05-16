use std::sync::Arc;

use anyhow::Result;
use nekoton_utils::*;
use serde::{Deserialize, Serialize};
use ton_block::{Block, Deserializable, MsgAddressInt};
use ton_types::{Cell, UInt256};

use crate::core::models::{NetworkCapabilities, ReliableBehavior};
use crate::external::{self, JrpcConnection};

use super::models::{PollContractState, RawContractState, RawTransaction};
use super::utils::*;
use super::{Transport, TransportInfo};

use self::models::*;

mod models;

pub struct JrpcTransport {
    connection: Arc<dyn JrpcConnection>,
    config_cache: ConfigCache,
    accounts_cache: AccountsCache,
}

impl JrpcTransport {
    pub fn new(connection: Arc<dyn JrpcConnection>) -> Self {
        Self {
            connection,
            config_cache: ConfigCache::new(false),
            accounts_cache: AccountsCache::new(),
        }
    }

    async fn fetch_config(&self) -> Result<ConfigResponse> {
        let req = external::JrpcRequest {
            data: make_jrpc_request("getBlockchainConfig", &()),
            requires_db: true,
        };
        self.connection
            .post(req)
            .await
            .map(|data| tiny_jsonrpc::parse_response(&data))?
            .map(|block: GetBlockchainConfigResponse| ConfigResponse {
                global_id: block.global_id,
                seqno: block.seqno,
                config: block.config,
            })
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
impl Transport for JrpcTransport {
    fn info(&self) -> TransportInfo {
        TransportInfo {
            max_transactions_per_fetch: 50,
            reliable_behavior: ReliableBehavior::IntensivePolling,
            has_key_blocks: true,
        }
    }

    async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        let req = external::JrpcRequest {
            data: make_jrpc_request("sendMessage", &SendMessage { message }),
            requires_db: false,
        };
        self.connection.post(req).await.map(|_| ())
    }

    async fn get_contract_state(&self, address: &MsgAddressInt) -> Result<RawContractState> {
        if let Some(known_state) = self.accounts_cache.get_account_state(address) {
            if let Some(last_trans_lt) = known_state.last_known_trans_lt() {
                let poll = self.poll_contract_state(address, last_trans_lt).await?;
                return Ok(match poll.to_changed() {
                    Ok(contract) => {
                        self.accounts_cache.update_account_state(address, &contract);
                        contract
                    }
                    Err(timings) => {
                        let mut known_state = known_state.as_ref().clone();
                        known_state.update_timings(timings);
                        known_state
                    }
                });
            }
        }

        let req = external::JrpcRequest {
            data: make_jrpc_request(
                "getContractState",
                &GetContractState {
                    address,
                    last_transaction_lt: None,
                },
            ),
            requires_db: false,
        };
        let data = self.connection.post(req).await?;
        let response = tiny_jsonrpc::parse_response::<RawContractState>(&data)?;
        self.accounts_cache.update_account_state(address, &response);
        Ok(response)
    }

    async fn get_library_cell(&self, hash: &UInt256) -> Result<Option<Cell>> {
        let req = external::JrpcRequest {
            data: make_jrpc_request("getLibraryCell", &GetLibraryCell { hash }),
            requires_db: false,
        };

        #[derive(Deserialize)]
        struct LibraryCellResponse {
            cell: Option<String>,
        }

        let data = self.connection.post(req).await?;

        let response = tiny_jsonrpc::parse_response::<LibraryCellResponse>(&data)?;
        let cell = match response.cell {
            Some(boc) => {
                let bytes = base64::decode(boc)?;
                Some(ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())?)
            }
            None => None,
        };

        Ok(cell)
    }

    async fn poll_contract_state(
        &self,
        address: &MsgAddressInt,
        last_trans_lt: u64,
    ) -> Result<PollContractState> {
        let req = external::JrpcRequest {
            data: make_jrpc_request(
                "getContractState",
                &GetContractState {
                    address,
                    last_transaction_lt: Some(last_trans_lt),
                },
            ),
            requires_db: false,
        };
        let data = self.connection.post(req).await?;
        let response = tiny_jsonrpc::parse_response::<PollContractState>(&data)?;
        if let Ok(new_state) = response.clone().to_changed() {
            self.accounts_cache
                .update_account_state(address, &new_state);
        }
        Ok(response)
    }

    async fn get_accounts_by_code_hash(
        &self,
        code_hash: &ton_types::UInt256,
        limit: u8,
        continuation: &Option<MsgAddressInt>,
    ) -> Result<Vec<MsgAddressInt>> {
        let req = external::JrpcRequest {
            data: make_jrpc_request(
                "getAccountsByCodeHash",
                &GetAccountsByCodeHash {
                    limit: limit as u32,
                    continuation,
                    code_hash,
                },
            ),
            requires_db: true,
        };
        let data = self.connection.post(req).await?;

        #[derive(Deserialize)]
        struct AddressWrapper(#[serde(with = "serde_address")] MsgAddressInt);

        Ok(tiny_jsonrpc::parse_response::<Vec<AddressWrapper>>(&data)?
            .into_iter()
            .map(|AddressWrapper(address)| address)
            .collect())
    }

    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from_lt: u64,
        count: u8,
    ) -> Result<Vec<RawTransaction>> {
        let req = external::JrpcRequest {
            data: make_jrpc_request(
                "getTransactionsList",
                &GetTransactions {
                    limit: count as u64,
                    last_transaction_lt: (from_lt != u64::MAX).then_some(from_lt),
                    account: address,
                },
            ),
            requires_db: true,
        };
        let response = self.connection.post(req).await?;
        let data: Vec<String> = tiny_jsonrpc::parse_response(&response)?;
        data.iter().map(|boc| decode_raw_transaction(boc)).collect()
    }

    async fn get_transaction(&self, id: &ton_types::UInt256) -> Result<Option<RawTransaction>> {
        let req = external::JrpcRequest {
            data: make_jrpc_request("getTransaction", &GetTransaction { id }),
            requires_db: true,
        };
        let response = self.connection.post(req).await?;
        let data: Option<String> = tiny_jsonrpc::parse_response(&response)?;
        data.map(|boc| decode_raw_transaction(&boc)).transpose()
    }

    async fn get_dst_transaction(
        &self,
        message_hash: &ton_types::UInt256,
    ) -> Result<Option<RawTransaction>> {
        let req = external::JrpcRequest {
            data: make_jrpc_request("getDstTransaction", &GetDstTransaction { message_hash }),
            requires_db: true,
        };
        let response = self.connection.post(req).await?;
        let data: Option<String> = tiny_jsonrpc::parse_response(&response)?;
        data.map(|boc| decode_raw_transaction(&boc)).transpose()
    }

    async fn get_latest_key_block(&self) -> Result<Block> {
        let req = external::JrpcRequest {
            data: make_jrpc_request("getLatestKeyBlock", &()),
            requires_db: true,
        };
        self.connection
            .post(req)
            .await
            .map(|data| tiny_jsonrpc::parse_response(&data))?
            .map(|block: GetBlockResponse| block.block)
    }

    async fn get_capabilities(&self, clock: &dyn Clock) -> Result<NetworkCapabilities> {
        let (capabilities, _) = self
            .config_cache
            .get_blockchain_config(clock, false, || self.fetch_config())
            .await?;
        Ok(capabilities)
    }

    async fn get_blockchain_config(
        &self,
        clock: &dyn Clock,
        force: bool,
    ) -> Result<ton_executor::BlockchainConfig> {
        let (_, config) = self
            .config_cache
            .get_blockchain_config(clock, force, || self.fetch_config())
            .await?;
        Ok(config)
    }
}

pub fn make_jrpc_request<S>(method: &str, params: &S) -> String
where
    S: Serialize,
{
    serde_json::to_string(&JrpcRequest { method, params }).trust_me()
}

pub struct JrpcRequest<'a, T> {
    method: &'a str,
    params: &'a T,
}

impl<'a, T> serde::Serialize for JrpcRequest<'a, T>
where
    T: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut ser = serializer.serialize_struct("JrpcRequest", 4)?;
        ser.serialize_field("jsonrpc", "2.0")?;
        ser.serialize_field("id", &1)?;
        ser.serialize_field("method", self.method)?;
        ser.serialize_field("params", self.params)?;
        ser.end()
    }
}

fn decode_raw_transaction(boc: &str) -> Result<RawTransaction> {
    let bytes = base64::decode(boc)?;
    let cell = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())?;
    let hash = cell.repr_hash();
    let data = ton_block::Transaction::construct_from_cell(cell)?;
    Ok(RawTransaction { hash, data })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use futures_util::StreamExt;
    use nekoton_contracts::jetton;

    use super::*;

    struct Client {
        url: String,
        client: reqwest::Client,
    }

    impl Client {
        fn new(url: &str) -> Self {
            Self {
                url: url.to_string(),
                client: reqwest::Client::new(),
            }
        }
    }

    #[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
    #[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
    impl JrpcConnection for Client {
        async fn post(&self, req: external::JrpcRequest) -> Result<String> {
            println!("{req:?}");
            let text = self
                .client
                .post(&self.url)
                .body(req.data)
                .header("Content-Type", "application/json")
                .send()
                .await?
                .text()
                .await?;
            // println!("{}", text);
            Ok(text)
        }
    }

    #[tokio::test]
    async fn test_library_cells() {
        let transport = JrpcTransport::new(Arc::new(Client::new("https://jrpc-ton.broxus.com")));
        let result = transport
            .get_library_cell(
                &UInt256::from_str(
                    "4f4f10cb9a30582792fb3c1e364de5a6fbe6fe04f4167f1f12f83468c767aeb3",
                )
                .unwrap(),
            )
            .await
            .unwrap();

        match result {
            Some(cell) => println!("{:?}", cell.repr_hash()),
            None => println!("No library cell"),
        }
    }

    #[tokio::test]
    async fn test_transactions_stream() -> Result<()> {
        let transport =
            JrpcTransport::new(Arc::new(Client::new("https://jrpc.everwallet.net/rpc")));

        let mut from_lt = 30526271000007;
        let until_lt = 26005429000001;
        let test_address =
            "0:cd809fb1cde24b6d3cd4a3dd9102e10c0f73ddfa21c7118f233dc7309bbb0b73".parse()?;

        let mut transactions = crate::core::utils::request_transactions(
            &transport,
            &test_address,
            from_lt,
            Some(until_lt),
            2,
            None,
        );

        while let Some(transactions) = transactions.next().await {
            for transaction in transactions? {
                assert_eq!(transaction.data.lt, from_lt);
                from_lt = transaction.data.prev_trans_lt;
            }
        }

        assert_eq!(from_lt, until_lt);
        Ok(())
    }

    #[tokio::test]
    async fn test_connection() -> Result<()> {
        let transport =
            JrpcTransport::new(Arc::new(Client::new("https://jrpc.everwallet.net/rpc")));
        let address = MsgAddressInt::from_str(
            "-1:3333333333333333333333333333333333333333333333333333333333333333",
        )?;
        transport.get_contract_state(&address).await?;
        transport
            .get_transactions(&address, 21968513000000, 10)
            .await?;
        
        transport
            .get_transaction(&ton_types::UInt256::from_slice(
                &hex::decode("4a0a06bfbfaba4da8fcc7f5ad617fdee5344d954a1794e35618df2a4b349d15c")
                    .unwrap(),
            ))
            .await?
            .unwrap();

        let setcode_multisig_code_hash = ton_types::UInt256::from_str(
            "e2b60b6b602c10ced7ea8ede4bdf96342c97570a3798066f3fb50a4b2b27a208",
        )?;

        let mut continuation = None;
        loop {
            let contracts = transport
                .get_accounts_by_code_hash(&setcode_multisig_code_hash, 50, &continuation)
                .await?;

            continuation = contracts.last().cloned();
            if continuation.is_none() {
                break;
            }
        }

        transport.get_latest_key_block().await?;

        Ok(())
    }

    #[tokio::test]
    async fn jetton_wallet_data() -> Result<()> {
        let transport = Arc::new(JrpcTransport::new(Arc::new(Client::new(
            "https://jrpc-ton.broxus.com",
        ))));

        let address = MsgAddressInt::from_str(
            "0:f5308490402448489540c8b55dc04a3c5a2140c525f5ef77941d314fcf615d7c",
        )?;

        let _wallet_data =
            crate::core::jetton_wallet::get_wallet_data(&SimpleClock, transport, &address).await?;

        Ok(())
    }

    #[tokio::test]
    async fn jetton_wallet_address() -> Result<()> {
        let transport = Arc::new(JrpcTransport::new(Arc::new(Client::new(
            "https://jrpc-ton.broxus.com",
        ))));

        let root = MsgAddressInt::from_str(
            "0:09f2e59dec406ab26a5259a45d7ff23ef11f3e5c7c21de0b0d2a1cbe52b76b3d",
        )?;

        let owner = MsgAddressInt::from_str(
            "0:43327c3d453bf0232b516d56d9899c7d7eba6128c319f3602b9b70ea2e2c9135",
        )?;

        let state = match transport.get_contract_state(&root).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists { .. } => {
                unreachable!()
            }
        };

        let token_address =
            jetton::RootTokenContract(state.as_context(&SimpleClock)).get_wallet_address(&owner)?;

        let expected_token_address = MsgAddressInt::from_str(
            "0:554e3918347da68aec7b7dd4cc28b090ebf3b398eb11fedb49c6eee3acd721fe",
        )?;
        assert_eq!(token_address, expected_token_address);

        Ok(())
    }
}
