mod models;

use nekoton_abi::{GenTimings, LastTransactionId, TransactionId};
use nekoton_utils::{pack_std_smc_addr, Clock};
use std::sync::Arc;
use ton_block::{
    AccountStorage, AccountStuff, Block, CurrencyCollection, GetRepresentationHash, Grams, Message,
    MsgAddressInt, Serializable, StorageInfo, VarUInteger7,
};
use ton_executor::BlockchainConfig;
use ton_types::{Cell, UInt256};

use super::{Transport, TransportInfo};
use crate::external::TonConnection;
use crate::models::{NetworkCapabilities, ReliableBehavior};
use crate::transport::models::{
    ExistingContract, PollContractState, RawContractState, RawTransaction,
};
use crate::transport::ton::models::*;
use crate::transport::utils::AccountsCache;

pub struct TonTransport {
    connection: Arc<dyn TonConnection>,
    accounts_cache: AccountsCache,
}

impl TonTransport {
    pub fn new(connection: Arc<dyn TonConnection>) -> Self {
        Self {
            connection,
            accounts_cache: AccountsCache::new(),
        }
    }
    async fn get_latest_block(&self) -> anyhow::Result<LatestBlock> {
        let result = self.connection.send_get("block/latest").await?;
        let result = match result {
            Some(t) => t,
            None => anyhow::bail!("Address or block not found"),
        };
        let result = serde_json::from_str(&result)?;
        Ok(result)
    }

    // pub async fn get_full_block(&self, seqno: u32) -> anyhow::Result<FullBlock> {
    //     let result = self.connection.send_get(&format!("block/{seqno}")).await?;
    //     let result = serde_json::from_value(result)?;
    //     Ok(result)
    // }

    // pub async fn get_full_block_by_utime(&self, utime: u64) -> anyhow::Result<FullBlock> {
    //     let result = self.connection.send_get(&format!("block/utime/{utime}")).await?;
    //     let result = serde_json::from_value(result)?;
    //     Ok(result)
    // }

    async fn get_account_state(
        &self,
        block_seqno: u32,
        address: &MsgAddressInt,
    ) -> anyhow::Result<Option<AccountStateResult>> {
        let base64_address = pack_std_smc_addr(true, address, false)?;
        let result = self
            .connection
            .send_get(&format!("block/{block_seqno}/{base64_address}"))
            .await;
        let result = match result {
            Ok(Some(result)) => Some(serde_json::from_str(&result)?),
            Ok(None) => return Ok(None),
            Err(err) => return Err(err),
        };
        Ok(result)
    }

    async fn check_account_changed_ext(
        &self,
        address: &MsgAddressInt,
        since_lt: u64,
    ) -> anyhow::Result<PollContractState> {
        let latest_block = self.get_latest_block().await?;
        let result = self
            .check_account_changed(latest_block.last.seqno, address, since_lt)
            .await?;
        let state = self
            .get_contract_state_ext(latest_block.last.seqno, latest_block.now, address)
            .await?;

        let state = match (result.changed, state) {
            (false, RawContractState::Exists(_)) => PollContractState::Unchanged {
                timings: GenTimings::Known {
                    gen_lt: 0,
                    gen_utime: latest_block.now,
                },
            },
            (true, RawContractState::Exists(contract)) => PollContractState::Exists(contract),
            (_, RawContractState::NotExists { timings }) => {
                PollContractState::NotExists { timings }
            }
        };

        Ok(state)
    }

    async fn get_contract_state_ext(
        &self,
        block_seqno: u32,
        block_utime: u32,
        address: &MsgAddressInt,
    ) -> anyhow::Result<RawContractState> {
        let state_opt = self.get_account_state(block_seqno, address).await?;

        let timings = GenTimings::Known {
            gen_lt: 0,
            gen_utime: block_utime,
        }; //TODO: how to get gen_lt

        let state = match state_opt {
            None => return Ok(RawContractState::NotExists { timings }),
            Some(state) => state,
        };

        let account_state = match state.account.state {
            AccountState::Active { code, data } => ton_block::AccountState::AccountActive {
                state_init: ton_block::StateInit {
                    split_depth: None,
                    special: None,
                    code: Some(code),
                    data: Some(data),
                    library: Default::default(),
                },
            },
            AccountState::Frozen { state_init_hash } => {
                ton_block::AccountState::AccountFrozen { state_init_hash }
            }
            AccountState::Uninit => ton_block::AccountState::AccountUninit,
        };

        let mut balance = CurrencyCollection::new();
        balance.grams = Grams::new(state.account.balance.coins)?;
        for (key, value) in state.account.balance.currencies.unwrap_or_default() {
            balance.set_other(key, value)?;
        }

        let used = state.account.storage_stat.used;

        let stuff = AccountStuff {
            addr: address.clone(),
            storage_stat: StorageInfo {
                used: ton_block::StorageUsed {
                    cells: VarUInteger7::new(used.cells)?,
                    bits: VarUInteger7::new(used.bits)?,
                    public_cells: VarUInteger7::new(used.public_cells)?,
                },
                last_paid: state.account.storage_stat.last_paid,
                due_payment: match state.account.storage_stat.due_payment {
                    Some(due_payment) => Some(Grams::new(due_payment)?),
                    None => None,
                },
            },
            storage: AccountStorage {
                last_trans_lt: state
                    .account
                    .last_transaction
                    .as_ref()
                    .map(|x| x.lt)
                    .unwrap_or_default(),
                balance,
                state: account_state,
                init_code_hash: None,
            },
        };

        let contract_state = RawContractState::Exists(ExistingContract {
            account: stuff,
            timings,
            last_transaction_id: match state.account.last_transaction {
                Some(last) => LastTransactionId::Exact(TransactionId {
                    lt: last.lt,
                    hash: last.hash,
                }),
                None => LastTransactionId::Inexact { latest_lt: 0 },
            },
        });

        Ok(contract_state)
    }

    async fn check_account_changed(
        &self,
        block_seqno: u32,
        address: &MsgAddressInt,
        since_lt: u64,
    ) -> anyhow::Result<AccountChangedResult> {
        let base64_address = pack_std_smc_addr(true, address, false)?;
        let result = self
            .connection
            .send_get(&format!(
                "block/{block_seqno}/{base64_address}/changed/{since_lt}"
            ))
            .await?;

        let result = match result {
            Some(t) => t,
            None => anyhow::bail!("Address or block not found"),
        };

        let result = serde_json::from_str(&result)?;
        Ok(result)
    }

    async fn get_config<I>(&self, block_seqno: u32, params: I) -> anyhow::Result<ConfigResult>
    where
        I: IntoIterator<Item = u32>,
    {
        let params_string = params
            .into_iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let result = self
            .connection
            .send_get(&format!("block/{block_seqno}/config/{params_string}"))
            .await?;

        let result = match result {
            Some(t) => t,
            None => anyhow::bail!("Block not found"),
        };

        let result = serde_json::from_str(&result)?;
        Ok(result)
    }

    async fn get_account_transactions(
        &self,
        address: &MsgAddressInt,
        lt: u64,
    ) -> anyhow::Result<AccountTransactionsResult> {
        let base64_address = pack_std_smc_addr(true, address, false)?;
        let result = self
            .connection
            .send_get(&format!("account/{base64_address}/tx/{lt}/-"))
            .await?;

        let result = match result {
            Some(t) => t,
            None => anyhow::bail!("Address not found"),
        };
        let result = serde_json::from_str(&result)?;
        Ok(result)
    }

    async fn send_message(&self, message_cell: Cell) -> anyhow::Result<()> {
        let bytes = ton_types::serialize_toc(&message_cell)?;
        let boc = base64::encode(bytes);
        let body = serde_json::to_string(&MessageBoc { boc })?;

        self.connection.send_post(&body, "/send").await?;
        Ok(())
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
impl Transport for TonTransport {
    fn info(&self) -> TransportInfo {
        TransportInfo {
            max_transactions_per_fetch: 20,
            reliable_behavior: ReliableBehavior::IntensivePolling,
            has_key_blocks: false,
        }
    }

    async fn send_message(&self, message: &Message) -> anyhow::Result<()> {
        let cell = message.serialize()?;
        self.send_message(cell).await
    }

    async fn get_contract_state(
        &self,
        address: &MsgAddressInt,
    ) -> anyhow::Result<RawContractState> {
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

        let latest_block = self.get_latest_block().await?;
        let state = self
            .get_contract_state_ext(latest_block.last.seqno, latest_block.now, address)
            .await?;
        self.accounts_cache.update_account_state(address, &state);
        Ok(state)
    }

    async fn get_library_cell(&self, _: &UInt256) -> anyhow::Result<Option<Cell>> {
        Ok(None)
    }

    async fn poll_contract_state(
        &self,
        address: &MsgAddressInt,
        last_transaction_lt: u64,
    ) -> anyhow::Result<PollContractState> {
        self.check_account_changed_ext(address, last_transaction_lt)
            .await
    }

    async fn get_accounts_by_code_hash(
        &self,
        _: &UInt256,
        _: u8,
        _: &Option<MsgAddressInt>,
    ) -> anyhow::Result<Vec<MsgAddressInt>> {
        todo!()
    }

    async fn get_transactions(
        &self,
        address: &MsgAddressInt,
        from_lt: u64,
        count: u8,
    ) -> anyhow::Result<Vec<RawTransaction>> {
        const AT_MOST: usize = 20;

        let mut remaining = count;
        let mut transactions = Vec::with_capacity(count as usize);

        loop {
            let result = self.get_account_transactions(address, from_lt).await?;
            let len = result.transactions.len();
            let to_process = if len > remaining as usize {
                result
                    .transactions
                    .into_iter()
                    .take(remaining as usize)
                    .collect::<Vec<_>>()
            } else {
                result.transactions
            };

            for t in &to_process {
                transactions.push(RawTransaction {
                    hash: t.hash()?,
                    data: t.clone(),
                });
            }
            remaining = remaining.saturating_sub(len as u8);

            if AT_MOST > len || remaining == 0 {
                break;
            }

            if let Some(last) = transactions.last() {
                if last.data.prev_trans_lt == 0 {
                    break;
                }
            }
        }

        Ok(transactions)
    }

    async fn get_transaction(&self, _: &UInt256) -> anyhow::Result<Option<RawTransaction>> {
        todo!()
    }

    async fn get_dst_transaction(&self, _: &UInt256) -> anyhow::Result<Option<RawTransaction>> {
        todo!()
    }

    async fn get_latest_key_block(&self) -> anyhow::Result<Block> {
        todo!()
    }

    async fn get_capabilities(&self, _: &dyn Clock) -> anyhow::Result<NetworkCapabilities> {
        todo!()
    }

    async fn get_blockchain_config(
        &self,
        _: &dyn Clock,
        _: bool,
    ) -> anyhow::Result<BlockchainConfig> {
        let latest_block = self.get_latest_block().await?;
        let config = self
            .get_config(latest_block.last.seqno, vec![8, 20, 21, 24, 25, 18, 31])
            .await?;
        if let Some(config) = config.config {
            let config = ton_block::ConfigParams::with_root(config.cell);
            return BlockchainConfig::with_config(config, 0);
        }

        anyhow::bail!("Failed to get blockchain config")
    }
}

#[cfg(test)]
pub mod tests {
    use nekoton_utils::{unpack_std_smc_addr, SimpleClock};
    use reqwest::Url;
    use std::sync::Arc;

    use crate::core::generic_contract::{GenericContract, GenericContractSubscriptionHandler};
    use crate::external::TonConnection;
    use crate::models::{ContractState, PendingTransaction, Transaction, TransactionsBatchInfo};
    use crate::transport::ton::TonTransport;
    use crate::transport::Transport;

    #[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
    #[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
    impl TonConnection for reqwest::Client {
        async fn send_get(&self, path: &str) -> anyhow::Result<Option<String>> {
            let base = Url::parse("https://mainnet-v4.tonhubapi.com")?;
            let path = base.join(path)?;

            let result = self
                .get(path)
                .header("ContentType", "application/json")
                .send()
                .await?;

            if matches!(result.status(), reqwest::StatusCode::NOT_FOUND) {
                return Ok(None);
            }

            let result = result.text().await?;
            Ok(Some(result))
        }

        async fn send_post(&self, _: &str, _: &str) -> anyhow::Result<Option<String>> {
            todo!()
        }
    }

    #[tokio::test]
    async fn test_account_state() -> anyhow::Result<()> {
        let client = reqwest::Client::new();
        let address =
            unpack_std_smc_addr("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N", true)?;
        let transport = TonTransport::new(Arc::new(client));
        let state = transport.get_contract_state(&address).await?;
        println!("{:?}", state);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_transactions() -> anyhow::Result<()> {
        let client = reqwest::Client::new();
        let address =
            unpack_std_smc_addr("EQCo6VT63H1vKJTiUo6W4M8RrTURCyk5MdbosuL5auEqpz-C", true)?;
        let transport = TonTransport::new(Arc::new(client));
        let transactions = transport
            .get_transactions(&address, 27668319000001, u8::MAX)
            .await?;

        let mut prev_tx_lt = transactions.first().unwrap().data.lt;
        for i in &transactions {
            assert_eq!(i.data.lt, prev_tx_lt);
            prev_tx_lt = i.data.prev_trans_lt;
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_get_config() -> anyhow::Result<()> {
        let client = reqwest::Client::new();
        let transport = TonTransport::new(Arc::new(client));
        let config = transport.get_blockchain_config(&SimpleClock, true).await?;
        println!("{:?}", config.get_fwd_prices(true));
        println!("{:?}", config.get_fwd_prices(false));
        Ok(())
    }

    #[derive(Copy, Clone, Debug)]
    pub struct SimpleHandler;
    impl GenericContractSubscriptionHandler for SimpleHandler {
        fn on_message_sent(
            &self,
            _: PendingTransaction,
            _: Option<Transaction>,
        ) {
            println!("on_message_sent");
        }

        fn on_message_expired(&self, _: PendingTransaction) {
            println!("on_message_expired");
        }

        fn on_state_changed(&self, _: ContractState) {
            println!("on_state_changed");
        }

        fn on_transactions_found(
            &self,
            _: Vec<Transaction>,
            _: TransactionsBatchInfo,
        ) {
            println!("on_transactions_found");
        }
    }

    #[tokio::test]
    async fn subscription_test() -> anyhow::Result<()> {
        let client = reqwest::Client::new();
        let transport = TonTransport::new(Arc::new(client));
        let address =
            unpack_std_smc_addr("UQBXJ9VgpXcBGYGDXYurquCsl3LV0bLmsIWuhv9VmIkxCm8q", true)?;
        let sub = GenericContract::subscribe(
            Arc::new(SimpleClock),
            Arc::new(transport),
            address,
            Arc::new(SimpleHandler),
            true,
        )
        .await?;
        let state = sub.contract_state();
        println!("{:?}", state);
        Ok(())
    }
}
