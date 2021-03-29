pub mod models;

use std::convert::TryFrom;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use async_trait::async_trait;
use futures::{Future, FutureExt, Stream, StreamExt};
use ton_block::MsgAddressInt;

use self::models::{AccountState, Transaction, TransactionId, TransactionsBatchInfo};
use crate::core::models::{GenTimings, LastTransactionId, PendingTransaction};
use crate::transport::models::{ContractState, TransactionFull};
use crate::transport::Transport;

pub struct TonInterface {
    transport: Box<dyn Transport>,
}

impl TonInterface {
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self { transport }
    }

    pub async fn send_message(&self, message: &ton_block::Message) -> Result<()> {
        self.transport.send_message(message).await
    }

    pub fn set_transport(&mut self, transport: Box<dyn Transport>) {
        self.transport = transport;
    }
}

#[derive(Clone)]
pub struct MainWalletSubscription {
    transport: Arc<dyn Transport>,
    handler: Arc<dyn AccountSubscriptionHandler>,
    address: MsgAddressInt,
    account_state: AccountState,
    latest_known_transaction: Option<TransactionId>,
    pending_transactions: Vec<PendingTransaction>,
}

impl MainWalletSubscription {
    pub fn address(&self) -> &MsgAddressInt {
        &self.address
    }

    pub fn account_state(&self) -> &AccountState {
        &self.account_state
    }

    pub fn pending_transactions(&self) -> &[PendingTransaction] {
        &self.pending_transactions
    }

    pub async fn subscribe(
        transport: Arc<dyn Transport>,
        address: MsgAddressInt,
        handler: Arc<dyn AccountSubscriptionHandler>,
    ) -> Result<MainWalletSubscription> {
        let mut result = MainWalletSubscription {
            transport,
            handler,
            address,
            account_state: AccountState {
                balance: 0,
                gen_timings: GenTimings::Unknown,
                last_transaction_id: None,
                is_deployed: false,
            },
            latest_known_transaction: None,
            pending_transactions: Vec::new(),
        };

        if result.refresh_account_state().await? {
            let count = result.transport.max_transactions_per_fetch();
            result
                .refresh_latest_transactions(count, Some(count as usize))
                .await?;
        }

        Ok(result)
    }

    /// Requests current account state and notifies the handler if it was changed
    pub async fn refresh_account_state(&mut self) -> Result<bool> {
        let new_state = match self.transport.get_account_state(&self.address).await? {
            ContractState::NotExists => AccountState {
                balance: 0,
                gen_timings: GenTimings::Unknown,
                last_transaction_id: None,
                is_deployed: false,
            },
            ContractState::Exists {
                account,
                timings,
                last_transaction_id,
            } => AccountState {
                balance: account.storage.balance.grams.0 as u64,
                gen_timings: timings,
                last_transaction_id: Some(last_transaction_id),
                is_deployed: matches!(
                    account.storage.state,
                    ton_block::AccountState::AccountActive(_)
                ),
            },
        };

        match (
            &self.account_state.last_transaction_id,
            &new_state.last_transaction_id,
        ) {
            (None, Some(_)) => self.account_state = new_state,
            (Some(current), Some(new)) if current < new => self.account_state = new_state,
            _ => return Ok(false),
        }

        self.handler.on_state_changed(self.account_state.clone());

        Ok(true)
    }

    /// Requests the latest transactions and notifies the handler if some were found
    ///
    /// # Arguments
    ///
    /// * `initial_count` - optimistic prediction, that there were at most N new transactions
    /// * `limit` - max transaction count to be requested
    pub async fn refresh_latest_transactions(
        &mut self,
        initial_count: u8,
        limit: Option<usize>,
    ) -> Result<()> {
        let from = match self.account_state.last_transaction_id {
            Some(id) => id.to_transaction_id(),
            None => return Ok(()),
        };

        let mut new_latest_known_transaction = None;

        // clone request context, because `&mut self` is needed later
        let transport = self.transport.clone();
        let address = self.address.clone();
        let latest_known_transaction = self.latest_known_transaction;

        let mut transactions = request_transactions(
            transport.as_ref(),
            &address,
            from,
            latest_known_transaction.as_ref(),
            initial_count,
            limit,
        );

        while let Some((new_transactions, batch_info)) = transactions.next().await {
            let new_transactions = convert_transactions(new_transactions).collect::<Vec<_>>();
            if new_transactions.is_empty() {
                continue;
            }

            // requires `&mut self`, so `request_transactions` must use outer objects
            self.check_executed_transactions(&new_transactions);

            if new_latest_known_transaction.is_none() {
                new_latest_known_transaction =
                    new_transactions.first().map(|transaction| transaction.id);
            }

            self.handler
                .on_transactions_found(new_transactions, batch_info);
        }

        std::mem::drop(transactions);

        if let Some(id) = new_latest_known_transaction {
            self.latest_known_transaction = Some(id);
        }

        Ok(())
    }

    /// Loads older transactions since specified id and notifies the handler with them
    ///
    /// **NOTE: returns transactions, sorted by lt in descending order**
    pub async fn preload_transactions(&mut self, from: TransactionId) -> Result<()> {
        let transactions = self
            .transport
            .get_transactions(
                self.address.clone(),
                from,
                self.transport.max_transactions_per_fetch(),
            )
            .await?
            .into_iter()
            .filter_map(|transaction| {
                Transaction::try_from((transaction.hash, transaction.data)).ok()
            })
            .collect::<Vec<_>>();

        if let (Some(first), Some(last)) = (transactions.first(), transactions.last()) {
            let batch_info = TransactionsBatchInfo {
                min_lt: last.id.lt, // transactions in response are in descending order
                max_lt: first.id.lt,
                old: true,
            };

            self.handler.on_transactions_found(transactions, batch_info);
        }

        Ok(())
    }

    /// Searches executed pending transactions and notifies the handler if some were found
    fn check_executed_transactions(&mut self, transactions: &[Transaction]) {
        let handler = &self.handler;

        self.pending_transactions.retain(|pending| {
            let transaction = match transactions
                .iter()
                .find(|transaction| pending.eq(*transaction))
            {
                Some(transaction) => transaction,
                None => return true,
            };

            handler.on_message_sent(pending.clone(), transaction.clone());
            false
        });
    }

    /// Removes expired transactions and notifies the handler with them
    fn check_expired_transactions(&mut self, current_utime: u32) {
        let handler = &self.handler;

        self.pending_transactions.retain(|pending| {
            let expired = current_utime > pending.expire_at;
            if expired {
                handler.on_message_expired(pending.clone());
            }
            !expired
        })
    }
}

#[async_trait]
impl AccountSubscription for MainWalletSubscription {
    async fn send(
        &mut self,
        message: &ton_block::Message,
        expire_at: u32,
    ) -> Result<PendingTransaction> {
        let src = match message.header() {
            ton_block::CommonMsgInfo::ExtInMsgInfo(header) => {
                if header.dst == self.address {
                    None
                } else {
                    return Err(AccountSubscriptionError::InvalidMessageDestination.into());
                }
            }
            _ => return Err(AccountSubscriptionError::InvalidMessageType.into()),
        };

        let body_hash = message
            .body()
            .map(|body| body.hash(ton_types::cell::MAX_LEVEL))
            .unwrap_or_default();

        let pending_transaction = PendingTransaction {
            src,
            body_hash,
            expire_at,
        };

        self.pending_transactions.push(pending_transaction.clone());
        match self.transport.send_message(message).await {
            // return pending transaction on success
            Ok(()) => Ok(pending_transaction),
            // remove pending transaction from queue on error
            Err(e) => {
                if let Some(i) = self
                    .pending_transactions
                    .iter()
                    .position(|item| item.eq(&pending_transaction))
                {
                    self.pending_transactions.remove(i);
                }
                Err(e)
            }
        }
    }

    async fn refresh(&mut self) -> Result<()> {
        // optimistic prediction, that there were at most N new transactions
        const INITIAL_TRANSACTION_COUNT: u8 = 4;

        if self.refresh_account_state().await? {
            let count = u8::min(
                self.transport.max_transactions_per_fetch(),
                INITIAL_TRANSACTION_COUNT,
            );

            // get all new transactions until known id
            self.refresh_latest_transactions(count, None).await?;
        }

        if !self.pending_transactions.is_empty() {
            let current_utime = self.account_state.gen_timings.current_utime();
            self.check_expired_transactions(current_utime);
        }

        Ok(())
    }

    async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()> {
        let block = parse_block(&self.address, &self.account_state, block)?;

        if let Some((account_state, new_transactions)) = block.data {
            self.handler.on_state_changed(account_state);

            if let Some((new_transactions, batch_info)) = new_transactions {
                let new_transactions = convert_transactions(new_transactions)
                    .rev()
                    .collect::<Vec<_>>();
                self.check_executed_transactions(&new_transactions);
                if !new_transactions.is_empty() {
                    self.handler
                        .on_transactions_found(new_transactions, batch_info);
                }
            }
        }

        self.check_expired_transactions(block.current_utime);

        Ok(())
    }

    fn polling_method(&self) -> PollingMethod {
        if self.pending_transactions.is_empty() {
            PollingMethod::Manual
        } else {
            PollingMethod::Reliable
        }
    }
}

#[async_trait]
pub trait TransportSubscription {
    async fn subscribe_main_wallet(
        &self,
        address: MsgAddressInt,
        handler: Arc<dyn AccountSubscriptionHandler>,
    ) -> Result<MainWalletSubscription>;
}

pub trait AccountSubscriptionHandler: Send + Sync {
    /// Called when found transaction which is relative with one of the pending transactions
    fn on_message_sent(&self, pending_transaction: PendingTransaction, transaction: Transaction);

    /// Called when no transactions produced for the specific message before some expiration time
    fn on_message_expired(&self, pending_transaction: PendingTransaction);

    /// Called every time a new state is detected
    fn on_state_changed(&self, new_state: AccountState);

    /// Called every time new transactions are detected.
    /// - When new block found
    /// - When manually requesting the latest transactions (can be called several times)
    /// - When preloading transactions
    fn on_transactions_found(
        &self,
        transactions: Vec<Transaction>,
        batch_info: TransactionsBatchInfo,
    );
}

#[derive(Debug, Copy, Clone)]
pub enum PollingMethod {
    /// Manual polling once a minute or by a click.
    /// Used when there are no pending transactions
    Manual,
    /// Block-walking for GQL or fast refresh for ADNL.
    /// Used when there are some pending transactions
    Reliable,
}

#[async_trait]
pub trait AccountSubscription {
    /// Send a message to subscribed account and ensure it is sent or expired
    async fn send(
        &mut self,
        message: &ton_block::Message,
        expire_at: u32,
    ) -> Result<PendingTransaction>;

    /// Called by manual polling
    async fn refresh(&mut self) -> Result<()>;

    /// Called by block-walking
    async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()>;

    /// Returns current polling method
    fn polling_method(&self) -> PollingMethod;
}

#[derive(thiserror::Error, Debug)]
pub enum AccountSubscriptionError {
    #[error("Invalid message destination")]
    InvalidMessageDestination,
    #[error("Invalid message type")]
    InvalidMessageType,
    #[error("Invalid block")]
    InvalidBlock,
}

fn convert_transactions(
    transactions: Vec<TransactionFull>,
) -> impl Iterator<Item = Transaction> + DoubleEndedIterator {
    transactions
        .into_iter()
        .filter_map(|transaction| Transaction::try_from((transaction.hash, transaction.data)).ok())
}

fn request_transactions<'a>(
    transport: &'a dyn Transport,
    address: &'a MsgAddressInt,
    from: TransactionId,
    until: Option<&'a TransactionId>,
    initial_count: u8,
    limit: Option<usize>,
) -> LatestTransactions<'a> {
    let count = u8::min(initial_count, transport.max_transactions_per_fetch());

    LatestTransactions {
        address,
        until,
        transport,
        fut: Some(transport.get_transactions(address.clone(), from, count)),
        total_fetched: 0,
        limit,
    }
}

struct ParsedBlock {
    current_utime: u32,
    data: Option<(AccountState, Option<NewTransactions>)>,
}

impl ParsedBlock {
    #[inline]
    fn empty(utime: u32) -> Self {
        Self {
            current_utime: utime,
            data: None,
        }
    }

    #[inline]
    fn with_data(
        utime: u32,
        account_state: AccountState,
        new_transactions: Option<NewTransactions>,
    ) -> Self {
        Self {
            current_utime: utime,
            data: Some((account_state, new_transactions)),
        }
    }
}

fn parse_block(
    address: &MsgAddressInt,
    account_state: &AccountState,
    block: &ton_block::Block,
) -> Result<ParsedBlock> {
    use ton_block::{Deserializable, HashmapAugType};
    use ton_types::HashmapType;

    let info = block
        .info
        .read_struct()
        .map_err(|_| AccountSubscriptionError::InvalidBlock)?;

    let (account_block, balance) = match block
        .extra
        .read_struct()
        .and_then(|extra| extra.read_account_blocks())
        .and_then(|account_blocks| {
            account_blocks.get_with_aug(&address.address().get_bytestring(0).into())
        }) {
        Ok(Some(extra)) => extra,
        _ => return Ok(ParsedBlock::empty(info.gen_utime().0)),
    };

    let mut new_transactions = Vec::new();

    let mut latest_transaction_id: Option<TransactionId> = None;
    let mut is_deployed = account_state.is_deployed;

    for item in account_block.transactions().iter() {
        let transaction = match item.and_then(|(_, value)| {
            let cell = value.into_cell().reference(0)?;
            let hash = cell.repr_hash();

            ton_block::Transaction::construct_from_cell(cell)
                .map(|data| TransactionFull { hash, data })
        }) {
            Ok(transaction) => transaction,
            Err(_) => continue,
        };

        is_deployed = transaction.data.end_status == ton_block::AccountStatus::AccStateActive;

        if matches!(&latest_transaction_id, Some(id) if transaction.data.lt > id.lt) {
            latest_transaction_id = Some(TransactionId {
                lt: transaction.data.lt,
                hash: transaction.hash,
            })
        }

        new_transactions.push(transaction)
    }

    let new_account_state = AccountState {
        balance: balance.grams.0 as u64,
        gen_timings: GenTimings::Known {
            gen_lt: info.end_lt(),
            gen_utime: info.gen_utime().0,
        },
        last_transaction_id: latest_transaction_id
            .map(LastTransactionId::Exact)
            .or(account_state.last_transaction_id),
        is_deployed,
    };

    let new_transactions =
        if let (Some(first), Some(last)) = (new_transactions.first(), new_transactions.last()) {
            Some(TransactionsBatchInfo {
                min_lt: first.data.lt, // transactions in block info are in ascending order
                max_lt: last.data.lt,
                old: false,
            })
        } else {
            None
        }
        .map(|batch_info| (new_transactions, batch_info));

    Ok(ParsedBlock::with_data(
        info.gen_utime().0,
        new_account_state,
        new_transactions,
    ))
}

type NewTransactions = (Vec<TransactionFull>, TransactionsBatchInfo);

struct LatestTransactions<'a> {
    address: &'a MsgAddressInt,
    until: Option<&'a TransactionId>,
    transport: &'a dyn Transport,
    fut: Option<TransactionsFut<'a>>,
    total_fetched: usize,
    limit: Option<usize>,
}

type TransactionsFut<'a> = Pin<Box<dyn Future<Output = Result<Vec<TransactionFull>>> + Send + 'a>>;

impl<'a> Stream for LatestTransactions<'a> {
    type Item = NewTransactions;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let new_transactions = match self.fut.take() {
            Some(mut fut) => match fut.poll_unpin(cx) {
                Poll::Ready(result) => result,
                Poll::Pending => {
                    self.fut = Some(fut);
                    return Poll::Pending;
                }
            },
            None => return Poll::Ready(None),
        };

        let mut new_transactions = match new_transactions {
            Ok(transactions) => transactions,
            Err(_) => {
                // TODO: retry?
                return Poll::Ready(None);
            }
        };

        // retain only first elements with lt greater than `until.lt`
        if let Some(until) = self.until {
            new_transactions.truncate({
                let mut len = 0;
                for item in new_transactions.iter() {
                    if item.data.lt > until.lt {
                        len += 1;
                    } else {
                        break;
                    }
                }
                len
            });
        }

        // get batch info
        let (last, info) = match (new_transactions.first(), new_transactions.last()) {
            (Some(first), Some(last)) => {
                (
                    last,
                    TransactionsBatchInfo {
                        min_lt: last.data.lt, // transactions in response are in descending order
                        max_lt: first.data.lt,
                        old: false,
                    },
                )
            }
            _ => return Poll::Ready(None),
        };

        // check if there are no transactions left or all transactions were requested
        if last.data.prev_trans_lt == 0
            || matches!(self.until, Some(until) if last.data.prev_trans_lt <= until.lt)
        {
            return Poll::Ready(Some((new_transactions, info)));
        }

        // update counters
        self.total_fetched += new_transactions.len();

        let next_count = match self.limit {
            Some(limit) if self.total_fetched >= limit => {
                return Poll::Ready(Some((new_transactions, info)))
            }
            Some(limit) => usize::min(
                limit - self.total_fetched,
                self.transport.max_transactions_per_fetch() as usize,
            ) as u8,
            _ => self.transport.max_transactions_per_fetch(),
        };

        // If there are some unprocessed transactions left we should request remaining
        self.fut = Some(self.transport.get_transactions(
            self.address.clone(),
            TransactionId {
                lt: last.data.prev_trans_lt,
                hash: last.data.prev_trans_hash,
            },
            next_count,
        ));

        // Return result
        Poll::Ready(Some((new_transactions, info)))
    }
}
