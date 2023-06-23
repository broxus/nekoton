use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;

use nekoton_abi::Executor;
use nekoton_utils::Clock;
use ton_block::{
    Account, GetRepresentationHash, Message, MsgAddressInt, Serializable, Transaction,
};

use crate::transport::Transport;

pub struct TransactionsTreeStream {
    states: HashMap<MsgAddressInt, StoredAccount>,
    breakpoints: HashMap<i32, HashMap<MsgAddressInt, StoredAccount>>,
    messages: BinaryHeap<MessageWrapper>,
    config: ton_executor::BlockchainConfig,
    disable_signature_check: bool,
    unlimited_message_balance: bool,
    unlimited_account_balance: bool,
    transport: Arc<dyn Transport>,
    clock: Arc<dyn Clock>,
    use_empty_states: bool,
}

impl TransactionsTreeStream {
    pub fn new(
        message: Message,
        config: ton_executor::BlockchainConfig,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
        use_empty_states: bool,
    ) -> Self {
        Self {
            states: Default::default(),
            messages: BinaryHeap::from([MessageWrapper(message)]),
            config,
            disable_signature_check: false,
            unlimited_message_balance: false,
            unlimited_account_balance: false,
            transport,
            clock,
            breakpoints: Default::default(),
            use_empty_states,
        }
    }

    pub fn disable_signature_check(&mut self) -> &mut Self {
        self.disable_signature_check = true;
        self
    }

    pub fn unlimited_message_balance(&mut self) -> &mut Self {
        self.unlimited_message_balance = true;
        self
    }

    pub fn unlimited_account_balance(&mut self) -> &mut Self {
        self.unlimited_account_balance = true;
        self
    }

    pub fn set_account_state(&mut self, address: MsgAddressInt, state: StoredAccount) {
        self.states.insert(address, state);
    }

    pub fn get_account_states(&self) -> HashMap<MsgAddressInt, StoredAccount> {
        self.states.clone()
    }

    pub fn set_breakpoint(&mut self, breakpoint: i32) {
        self.breakpoints.insert(breakpoint, self.states.clone());
    }

    pub fn resume_breakpoint(&mut self, breakpoint: i32) {
        if let Some(state) = self.breakpoints.get(&breakpoint) {
            self.states = state.clone();
        }
    }

    pub fn message_queue(&self) -> &BinaryHeap<MessageWrapper> {
        &self.messages
    }

    pub fn retain_message_queue<F>(&mut self, mut f: F)
    where
        F: FnMut(&ton_block::Message) -> bool,
    {
        let f = |wrapper: &MessageWrapper| f(&wrapper.0);
        self.messages.retain(f);
    }

    pub async fn next(&mut self) -> TransactionTreeResult<Option<Transaction>> {
        match self.messages.pop() {
            Some(message) => self.step(message.0).await.map(Some),
            None => Ok(None),
        }
    }

    /// Pushes a message to the queue based on its lt
    pub fn push(&mut self, message: Message) {
        self.messages.push(MessageWrapper(message));
    }

    async fn step(&mut self, mut message: Message) -> TransactionTreeResult<Transaction> {
        const A_LOT: u64 = 1_000_000_000_000_000; // 1'000'000 ever

        if self.unlimited_message_balance {
            if let Some(header) = message.int_header_mut() {
                header.value.grams = ton_block::Grams::from(A_LOT);
            }
        }

        let dst = match message.dst() {
            Some(dst) => dst,
            _ => return Err(TransactionTreeError::ExternalOutMessage),
        };
        let StoredAccount {
            mut account,
            last_transaction_lt,
            last_paid,
        } = self.get_state(&dst).await?;

        if self.unlimited_account_balance {
            if let Account::Account(account) = &mut account {
                account.storage.balance.grams = ton_block::Grams::from(A_LOT);
            }
        }

        let now_ms = match last_paid {
            Some(last_paid) => std::cmp::max(last_paid as u64 * 1000, self.clock.now_ms_u64()),
            None => self.clock.now_ms_u64(),
        };

        let utime = (now_ms / 1000) as u32;
        let lt = last_transaction_lt;

        let mut executor =
            Executor::with_params(self.config.clone(), account, last_transaction_lt, utime, lt);
        if self.disable_signature_check {
            executor.disable_signature_check();
        }

        let tx = executor
            .run_mut(&message)
            .map_err(TransactionTreeError::ExecutionError)?;

        let last_transaction_lt = executor.last_transaction_lt();
        let last_paid = Some(utime);
        let account = executor.into_account();

        self.states.insert(
            dst,
            StoredAccount {
                account,
                last_transaction_lt,
                last_paid,
            },
        );

        tx.iterate_out_msgs(|x| {
            if x.is_internal() {
                self.messages.push(MessageWrapper(x));
            }
            Ok(true)
        })
        .map_err(TransactionTreeError::ExecutionError)?;

        Ok(tx)
    }

    async fn get_state(&self, address: &MsgAddressInt) -> TransactionTreeResult<StoredAccount> {
        match self.states.get(address) {
            None => {
                let account = if self.use_empty_states {
                    Account::default()
                } else {
                    self.transport
                        .get_contract_state(address)
                        .await
                        .map_err(TransactionTreeError::TransportError)?
                        .into_account()
                };

                let (last_transaction_lt, last_paid) = match &account {
                    Account::Account(account) => (
                        account.storage.last_trans_lt,
                        Some(account.storage_stat.last_paid),
                    ),
                    Account::AccountNone => (0, None),
                };

                Ok(StoredAccount {
                    account,
                    last_transaction_lt,
                    last_paid,
                })
            }
            Some(account) => Ok(account.clone()),
        }
    }
}

#[derive(Clone)]
pub struct StoredAccount {
    account: Account,
    last_transaction_lt: u64,
    last_paid: Option<u32>,
}

impl StoredAccount {
    pub fn new(account: Account) -> Self {
        let last_transaction_lt = account.last_tr_time().unwrap_or_default();
        let last_paid = account.last_paid();
        Self {
            account,
            last_transaction_lt,
            last_paid: Some(last_paid),
        }
    }
    pub fn get_state(&self) -> String {
        base64::encode(&self.account.write_to_bytes().unwrap())
    }
}

pub struct MessageWrapper(Message);

impl AsRef<Message> for MessageWrapper {
    fn as_ref(&self) -> &Message {
        &self.0
    }
}

impl Ord for MessageWrapper {
    fn cmp(&self, other: &Self) -> Ordering {
        // binary heap is max heap, so we need to reverse the order
        (
            std::cmp::Reverse(self.0.lt()),
            self.0.hash().unwrap_or_default(),
        )
            .cmp(&(
                std::cmp::Reverse(other.0.lt()),
                other.0.hash().unwrap_or_default(),
            ))
    }
}

impl PartialOrd for MessageWrapper {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for MessageWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.lt() == other.0.lt()
    }
}

impl Eq for MessageWrapper {}

type TransactionTreeResult<T> = Result<T, TransactionTreeError>;

#[derive(Debug, thiserror::Error)]
pub enum TransactionTreeError {
    #[error("External out message")]
    ExternalOutMessage,
    #[error("Transport error: {0}")]
    TransportError(anyhow::Error),
    #[error("Execution error: {0}")]
    ExecutionError(anyhow::Error),
}

#[cfg(test)]
#[cfg(feature = "jrpc_transport")]
mod test {
    use anyhow::Result;
    use std::str::FromStr;

    use crate::transport::jrpc::JrpcTransport;

    use nekoton_abi::TransactionParser;
    use nekoton_utils::{ConstClock, SimpleClock};

    use ton_block::{Deserializable, GetRepresentationHash, MsgAddrStd};

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test() -> Result<()> {
        let connection = reqwest::Client::new();
        let transport = Arc::new(JrpcTransport::new(Arc::new(connection)));

        let message = "te6ccgECCwEAAiAAAUWIAXu46jwbX3fmTWCR+sOP7NSfC9w6Ieb8ey6yinH94TG6DAEB4cHe2X7ZSGJPEZ8yA3uMskehJrNV78S5dTI7RkmjJAW2amO4V7DBILqXcTRnnbX9dABGRV0t4ouCjVWw6UYUZIR8drjTwv63I+aPTBLtMULU+zuEMSAmO8j5A00qizUXzUAAAGCAkCZIGLReThM7mRsgAgFlgAqvKvl06VY7ioloEDfQPiQRWucy+ulWduWysMlINu80gAAAAAAAAAAAAAAANOYs4BA4AwFraJxXwwAAAAAAAAAAAAAAADuaygCAEdfCW6r8F9gtsIJr8E6H1Ja37Lgfs8pNl/Q6IaXh4oBQBAFDgBe7jqPBtfd+ZNYJH6w4/s1J8L3Doh5vx7LrKKcf3hMbsAUBQ4Acl5cuaS7g+1r0QlJsMoOfX8ZyPtWIG7T55ZRTha2dV7AGA5UEABCKHoVX1z4AAAAAAAAAAAAAAAAF9eEAAAAAAAAAAAAAAAAAAALitIAYb2f1+Ut++m4JYQP7z76p5TDm3cCzftpl9YS+vMELftAJCAcAMgEAEIoehVfXPgAAAAAAAAAAAAAAAAX14QAAMgAAEIoehVfXPgAAAAAAAAAAAAAAAAX14QABYwAAAAAAAAAAAAAAAAABTVaAFKM/M3a62qPfKx2kmmb1rrQ47hELuahao6zMfz+bWfZQCgAgAAAAAAAAAAAAAAAAAAFLzA==";
        let message = Message::construct_from_base64(message)?;

        let config = transport.get_blockchain_config(&SimpleClock, true).await?;

        let time = 1657895160;
        let mut stream = TransactionsTreeStream::new(
            message,
            config,
            transport.clone(),
            Arc::new(ConstClock::from_secs(time)),
            true,
        );

        while let Some(tx) = stream.next().await.unwrap() {
            parse(&tx).await.ok();

            let descr = tx.read_description()?;
            let is_aborted = descr.is_aborted();
            let exit_code = descr.compute_phase_ref().and_then(|c| match c {
                ton_block::TrComputePhase::Vm(c) => Some(c.exit_code),
                ton_block::TrComputePhase::Skipped(_) => None,
            });

            println!(
                "{:x}: aborted={}, exit_code={:?}",
                tx.hash().unwrap(),
                is_aborted,
                exit_code
            );
        }

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_states() -> Result<()> {
        let connection = reqwest::Client::new();
        let transport = Arc::new(JrpcTransport::new(Arc::new(connection)));

        let message = "te6ccgEBBAEA0gABRYgBM+H2Exdbjf63Lplq1qvMw+lQe6guFTZX0u7MSlwU4cYMAQHh87ZYC1Kyg52QmML8rjkNNn4TSjvwQR5XQo5/UX2c+Nft+aaOMoeTailTwVQZwCqhLXgKiTrLU+/NkkY4tplcgvNWf9joJ6QJyXwr0vbypej62Iu6edG0oNvfoS8X0rVewAAAYjkezTEZJSap0zuZGyACAWWAEz4fYTF1uN/rcumWrWq8zD6VB7qC4VNlfS7sxKXBThxgAAAAAAAAAAAAAAAHc1lAADgDAAA=";
        // let message = "te6ccgECCwEAAiEAAUWIATPh9hMXW43+ty6ZatarzMPpUHuoLhU2V9LuzEpcFOHGDAEB4eCqhU7/PlCj0KyP6744g7cJopmuJxQyCzxeBACgGJTnDLwitE30sbAVsNSQQQTifvaOHHhOGCKq35zCE/A+MoHzVn/Y6CekCcl8K9L28qXo+tiLunnRtKDb36EvF9K1XsAAAGI5JYYXGSUoYlM7mRsgAgFlgAqvKvl06VY7ioloEDfQPiQRWucy+ulWduWysMlINu80gAAAAAAAAAAAAAAALLQXgBA4AwFraJxXwwAAAAAAAAAAAAAAADuaygCABEZC7FHFS9VUcSR5TBn+cO9HfJ5s2GqC8qQSN9nkZl1QBAFDgBM+H2Exdbjf63Lplq1qvMw+lQe6guFTZX0u7MSlwU4ccAUBQ4Acl5cuaS7g+1r0QlJsMoOfX8ZyPtWIG7T55ZRTha2dV7AGBLcGAAAAADzk2bwAAAAAAAAAAAAAAAAF9eEAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgoJCAcAMgEAAAAAPOTZvAAAAAAAAAAAAAAAAAX14QAAMgAAAAAAPOTZvAAAAAAAAAAAAAAAAAX14QAAYwAAAAAAAAAAAAAAAAA2WvaAFn2pcoBRA47HCs1oIbtAqmiM82DLucMwDpL4xEBXU5xwAAA=";
        let message = Message::construct_from_base64(message)?;

        let config = transport.get_blockchain_config(&SimpleClock, true).await?;

        let time = 1687460460;
        let mut stream = TransactionsTreeStream::new(
            message,
            config,
            transport.clone(),
            Arc::new(ConstClock::from_secs(time)),
            false,
        );

        let state = "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";
        let account = ton_block::Account::construct_from_base64(state).unwrap();
        let stored_account = StoredAccount {
            account,
            last_transaction_lt: 38404129000012,
            last_paid: Some(1684844890),
        };
        println!(
            "state balance {:?}",
            stored_account.account.balance().unwrap().grams
        );

        stream.set_account_state(
            MsgAddressInt::from_str(
                "0:99f0fb098badc6ff5b974cb56b55e661f4a83dd4170a9b2be97766252e0a70e3",
            )
            .unwrap(),
            stored_account,
        );

        while let Some(tx) = stream.next().await.unwrap() {
            parse(&tx).await.ok();

            let descr = tx.read_description()?;
            let is_aborted = descr.is_aborted();
            let exit_code = descr.compute_phase_ref().and_then(|c| match c {
                ton_block::TrComputePhase::Vm(c) => Some(c.exit_code),
                ton_block::TrComputePhase::Skipped(_) => None,
            });

            println!(
                "{:x}: aborted={}, exit_code={:?}",
                tx.hash().unwrap(),
                is_aborted,
                exit_code
            );
        }

        let new_state = stream
            .get_state(
                &MsgAddressInt::from_str(
                    "0:99f0fb098badc6ff5b974cb56b55e661f4a83dd4170a9b2be97766252e0a70e3",
                )
                .unwrap(),
            )
            .await
            .unwrap();

        println!(
            "new_state balance {:?}",
            new_state.account.balance().unwrap().grams
        );

        Ok(())
    }

    async fn parse(tx: &Transaction) -> Result<()> {
        let addr = MsgAddrStd::with_address(None, 0, tx.account_addr.clone());
        let abi = reqwest::get(format!("https://verify.everscan.io/abi/address/{addr}"))
            .await?
            .text()
            .await?;
        let contract = ton_abi::Contract::load(&abi)?;

        let parser = TransactionParser::builder()
            .events_list(contract.events.values().cloned())
            .function_in_list(contract.functions.values().cloned(), false)
            .functions_out_list(contract.functions.values().cloned(), false)
            .build_with_external_in()?;

        let parsed = parser.parse(tx)?;
        for parsed in parsed {
            if parsed.is_in_message {
                println!("{:x}: {}", tx.hash().unwrap(), parsed.name);
            }
        }

        Ok(())
    }
}
