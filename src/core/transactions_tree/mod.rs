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
    use std::str::FromStr;
    use anyhow::Result;

    use crate::transport::jrpc::JrpcTransport;

    use nekoton_abi::TransactionParser;
    use nekoton_utils::{ConstClock, SimpleClock};

    use ton_block::{Deserializable, GetRepresentationHash, MsgAddrStd};

    use super::*;

    #[tokio::test]
    async fn test() -> Result<()> {
        const FEE_MULTIPLIER: u128 = 2;


        let simulate_max = 100;
        let mut executed = 0;


        let connection = reqwest::Client::new();
        let transport = Arc::new(JrpcTransport::new(Arc::new(connection)));

        let message = "te6ccgECBgEAAUAAAUWIAfPq6ksCQX/kNfsY8xS5PTRd4WSjwjs5C/fod9ktFK+MDAEB4amL7qMv9ScFTr9uI3S256ZfAUpQd31utDJu/AVA1hxS2jd0rAxnfspEo74ULeUhlTgoep0zCaAXIwCmqmK0ZoPbC+VFMHA8uxUz/4awroOhSaOdkQsFCBVgevICP5+5SwAAAGKjpAyR2UBrl1M7mRsgAgFlgAbWXytRjCv/TJHSRYKrfWd3TY3IC3ClhOGd4nN5cpM/oAAAAAAAAAAAAAAAA7msoAA4AwGLc+IhQwAAAAAAAAAAAAAAADuaygCAAAff7szYGmr+bVED+268VSWLqK1DuRnaHZi5MJCegELAAAAAAAAAAAAAAAAAvrwgEAQBQ4AfPq6ksCQX/kNfsY8xS5PTRd4WSjwjs5C/fod9ktFK+MgFAAA=";
        let message = Message::construct_from_base64(message)?;

        let config = transport.get_blockchain_config(&SimpleClock, true).await?;

        let time = 1694608978;

        let mut tree = TransactionsTreeStream::new(message,
           config,
           transport.clone(),
           Arc::new(ConstClock::from_secs(time)));

        tree.unlimited_account_balance();
        tree.unlimited_message_balance();

        type Err = fn(Option<i32>) -> TokenWalletError;
        let check_exit_code = |tx: &ton_block::Transaction, err: Err| -> Result<()> {
            let descr = tx.read_description()?;
            if descr.is_aborted() {
                let exit_code = match descr {
                    ton_block::TransactionDescr::Ordinary(descr) => match descr.compute_ph {
                        ton_block::TrComputePhase::Vm(phase) => Some(phase.exit_code),
                        ton_block::TrComputePhase::Skipped(_) => None,
                    },
                    _ => None,
                };
                Err(err(exit_code).into())
            } else {
                Ok(())
            }
        };

        let mut attached_amount: u128 = 0;

        // Simulate source transaction
        let source_tx = tree.next().await?.ok_or(TokenWalletError::NoSourceTx)?;
        check_exit_code(&source_tx, TokenWalletError::SourceTxFailed)?;
        attached_amount += source_tx.total_fees.grams.as_u128() * FEE_MULTIPLIER;
        executed += 1;

        if source_tx.outmsg_cnt == 0 {
            return Err(TokenWalletError::NoDestTx.into());
        }



        let address = MsgAddressInt::from_str("0:4f4f10cb9a30582792fb3c1e364de5a6fbe6fe04f4167f1f12f83468c767aeb3").unwrap();

        if simulate_max == 2 {
            tree.retain_message_queue(|message| {
                message.state_init().is_none() && (message.src_ref() == Some(&address))
            });

            if tree.message_queue().len() != 1  {
                return Err(TokenWalletError::NoDestTx.into());
            }


            // Simulate destination transaction
            let dest_tx = tree.next().await?.ok_or(TokenWalletError::NoDestTx)?;
            check_exit_code(&dest_tx, TokenWalletError::DestinationTxFailed)?;
            attached_amount += dest_tx.total_fees.grams.as_u128() * FEE_MULTIPLIER;
        } else {
            'main: while executed < simulate_max   {
                if let Some(tx) = tree.next().await? {
                    check_exit_code(&tx, TokenWalletError::DestinationTxFailed)?;
                    if executed != 1 {
                        attached_amount += tx.total_fees.grams.as_u128() * FEE_MULTIPLIER;
                    }
                    executed += 1;
                } else {
                    break 'main;
                }
            }
        }


        println!("attached amount: {attached_amount}");
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

    #[derive(thiserror::Error, Debug)]
    enum TokenWalletError {
        #[error("Unknown version")]
        UnknownVersion,
        #[error("Invalid root token contract")]
        InvalidRootTokenContract,
        #[error("Invalid token wallet contract")]
        InvalidTokenWalletContract,
        #[error("Non-zero execution result code: {}", .0)]
        NonZeroResultCode(i32),
        #[error("Wallet not deployed")]
        WalletNotDeployed,
        #[error("No source transaction produced")]
        NoSourceTx,
        #[error("No destination transaction produced")]
        NoDestTx,
        #[error("Source transaction failed with exit code {0:?}")]
        SourceTxFailed(Option<i32>),
        #[error("Destination transaction failed with exit code {0:?}")]
        DestinationTxFailed(Option<i32>),
    }
}
