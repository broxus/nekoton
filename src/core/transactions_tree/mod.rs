use crate::transport::models::{ExistingContract, RawContractState};
use crate::transport::Transport;
use nekoton_abi::{Executor, GenTimings, LastTransactionId};
use nekoton_utils::{Clock, ConstClock, SimpleClock};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use ton_block::{Account, Message, MsgAddressInt, Transaction};

type Result<T> = std::result::Result<T, Error>;

pub struct TransactionsTreeStream {
    states: HashMap<MsgAddressInt, Account>,
    messages: VecDeque<Message>,
    config: ton_executor::BlockchainConfig,
    transport: Arc<dyn Transport>,
    clock: Arc<dyn Clock>,
}

impl TransactionsTreeStream {
    pub async fn stream(
        message: Message,
        transport: Arc<dyn Transport>,
        clock: Option<Arc<dyn Clock>>,
    ) -> Result<(Self, Transaction)> {
        let dst = match message.dst() {
            Some(dst) => dst,
            None => return Err(Error::ExternalOutMessage),
        };

        let dst_state = transport
            .get_contract_state(&dst)
            .await
            .map_err(Error::TransportError)?;

        let config = transport
            .get_blockchain_config(&nekoton_utils::SimpleClock)
            .await
            .map_err(Error::TransportError)?;

        let clock = clock.unwrap_or_else(|| Arc::new(SimpleClock));

        let state = dst_state.state();
        let mut executor = Executor::with_account(clock.as_ref(), config.clone(), state);

        let tx = executor.run_mut(&message).map_err(Error::ExecutionError)?;
        let state = executor.account().clone();

        let mut map = HashMap::new();
        map.insert(dst, state);

        let mut out_messages = VecDeque::new();
        tx.iterate_out_msgs(|x| {
            out_messages.push_back(x);
            Ok(true)
        })
        .map_err(Error::ExecutionError)?;

        Ok((
            Self {
                states: map,
                messages: out_messages,
                config,
                transport,
                clock,
            },
            tx,
        ))
    }

    pub async fn next(&mut self) -> Result<TreeItem> {
        let message = match self.messages.pop_front() {
            None => {
                return Ok(TreeItem::Finished);
            }
            Some(m) => m,
        };
        let tx = self.step(message).await?;

        Ok(tx)
    }

    async fn step(&mut self, message: Message) -> Result<TreeItem> {
        let dst = match message.dst() {
            Some(dst) => dst,
            None => return Ok(TreeItem::ShouldNotProduce),
        };
        let dst_state = self.get_state(&dst).await?;

        let dst_time = match &dst_state {
            Account::AccountNone => ConstClock::from_secs(self.clock.now_sec_u64()),
            Account::Account(a) => ConstClock::from_secs(a.storage_stat.last_paid as u64),
        };

        let mut executor = Executor::with_account(&dst_time, self.config.clone(), dst_state);
        let tx = executor.run_mut(&message).map_err(Error::ExecutionError)?;
        let state = executor.account().clone();
        self.states.insert(dst, state);

        let mut cnt = 0;
        tx.iterate_out_msgs(|x| {
            cnt += 1;
            self.messages.push_back(x);
            Ok(true)
        })
        .map_err(Error::ExecutionError)?;

        println!("Added {cnt} messages");

        Ok(TreeItem::Ok(tx))
    }

    async fn get_state(&self, address: &MsgAddressInt) -> Result<Account> {
        let state = self.states.get(address);
        let state = match state {
            None => self
                .transport
                .get_contract_state(address)
                .await
                .map_err(Error::TransportError)?
                .state(),
            Some(s) => s.clone(),
        };

        Ok(state)
    }

    /// returns modified account state after tree traversal
    pub fn state(&self, address: &MsgAddressInt) -> Option<RawContractState> {
        let state = self.states.get(address)?;
        let account = match state {
            Account::AccountNone => RawContractState::NotExists,
            Account::Account(a) => RawContractState::Exists(ExistingContract {
                account: a.clone(),
                timings: GenTimings::Unknown,
                last_transaction_id: LastTransactionId::Inexact {
                    latest_lt: a.storage.last_trans_lt,
                },
            }),
        };

        Some(account)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum TreeItem {
    Ok(Transaction),
    ShouldNotProduce,
    Finished,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
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
    use crate::transport::jrpc::JrpcTransport;

    use nekoton_abi::TransactionParser;
    use nekoton_utils::ConstClock;

    use ton_block::{Deserializable, GetRepresentationHash, MsgAddrStd};

    use super::*;

    #[tokio::test]
    async fn test() {
        let connection = reqwest::Client::new();
        let transport = JrpcTransport::new(Arc::new(connection));

        let message = "te6ccgECCwEAAiAAAUWIAXu46jwbX3fmTWCR+sOP7NSfC9w6Ieb8ey6yinH94TG6DAEB4cHe2X7ZSGJPEZ8yA3uMskehJrNV78S5dTI7RkmjJAW2amO4V7DBILqXcTRnnbX9dABGRV0t4ouCjVWw6UYUZIR8drjTwv63I+aPTBLtMULU+zuEMSAmO8j5A00qizUXzUAAAGCAkCZIGLReThM7mRsgAgFlgAqvKvl06VY7ioloEDfQPiQRWucy+ulWduWysMlINu80gAAAAAAAAAAAAAAANOYs4BA4AwFraJxXwwAAAAAAAAAAAAAAADuaygCAEdfCW6r8F9gtsIJr8E6H1Ja37Lgfs8pNl/Q6IaXh4oBQBAFDgBe7jqPBtfd+ZNYJH6w4/s1J8L3Doh5vx7LrKKcf3hMbsAUBQ4Acl5cuaS7g+1r0QlJsMoOfX8ZyPtWIG7T55ZRTha2dV7AGA5UEABCKHoVX1z4AAAAAAAAAAAAAAAAF9eEAAAAAAAAAAAAAAAAAAALitIAYb2f1+Ut++m4JYQP7z76p5TDm3cCzftpl9YS+vMELftAJCAcAMgEAEIoehVfXPgAAAAAAAAAAAAAAAAX14QAAMgAAEIoehVfXPgAAAAAAAAAAAAAAAAX14QABYwAAAAAAAAAAAAAAAAABTVaAFKM/M3a62qPfKx2kmmb1rrQ47hELuahao6zMfz+bWfZQCgAgAAAAAAAAAAAAAAAAAAFLzA==";
        let message = Message::construct_from_base64(message).unwrap();

        let time = 1657895160;
        let (mut stream, _first_tx) = TransactionsTreeStream::stream(
            message,
            Arc::new(transport),
            Some(Arc::new(ConstClock::from_secs(time))),
        )
        .await
        .unwrap();

        loop {
            let res = stream.next().await.unwrap();
            match res {
                TreeItem::Ok(tx) => {
                    if let Err(_e) = parse(&tx).await {}
                    let is_aborted = tx.read_description().unwrap().is_aborted();
                    if is_aborted {
                        let addr = MsgAddrStd::with_address(None, 0, tx.account_addr.clone());
                        let acc = stream.states.get(&MsgAddressInt::AddrStd(addr)).unwrap();
                        dbg!(acc);
                    }
                }
                TreeItem::ShouldNotProduce => {
                    println!("Should not produce");
                }
                TreeItem::Finished => break,
            }
        }
    }

    async fn parse(tx: &Transaction) -> anyhow::Result<()> {
        let addr = MsgAddrStd::with_address(None, 0, tx.account_addr.clone());
        let abi = reqwest::get(format!("https://verify.everscan.io/abi/address/{}", addr))
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
