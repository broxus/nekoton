use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use nekoton_abi::Executor;
use nekoton_utils::Clock;
use ton_block::{Account, Message, MsgAddressInt, Transaction};

use crate::transport::Transport;

pub struct TransactionsTreeStream {
    states: HashMap<MsgAddressInt, StoredAccount>,
    messages: VecDeque<Message>,
    config: ton_executor::BlockchainConfig,
    disable_signature_check: bool,
    unlimited_message_balance: bool,
    unlimited_account_balance: bool,
    transport: Arc<dyn Transport>,
    clock: Arc<dyn Clock>,
}

impl TransactionsTreeStream {
    pub fn new(
        message: Message,
        config: ton_executor::BlockchainConfig,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            states: Default::default(),
            messages: VecDeque::from([message]),
            config,
            disable_signature_check: false,
            unlimited_message_balance: false,
            unlimited_account_balance: false,
            transport,
            clock,
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

    pub fn message_queue(&self) -> &VecDeque<ton_block::Message> {
        &self.messages
    }

    pub fn retain_message_queue<F>(&mut self, f: F)
    where
        F: FnMut(&ton_block::Message) -> bool,
    {
        self.messages.retain(f);
    }

    pub async fn next(&mut self) -> TransactionTreeResult<Option<Transaction>> {
        match self.messages.pop_front() {
            Some(message) => self.step(message).await.map(Some),
            None => Ok(None),
        }
    }

    pub fn peek(&self) -> Option<&Message> {
        self.messages.front()
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
                self.messages.push_back(x);
            }
            Ok(true)
        })
        .map_err(TransactionTreeError::ExecutionError)?;

        Ok(tx)
    }

    async fn get_state(&self, address: &MsgAddressInt) -> TransactionTreeResult<StoredAccount> {
        match self.states.get(address) {
            None => {
                let account = self
                    .transport
                    .get_contract_state(address)
                    .await
                    .map_err(TransactionTreeError::TransportError)?
                    .into_account();

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
struct StoredAccount {
    account: Account,
    last_transaction_lt: u64,
    last_paid: Option<u32>,
}

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
