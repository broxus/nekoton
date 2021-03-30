use std::convert::TryFrom;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use futures::{Future, FutureExt, Stream};
use ton_block::MsgAddressInt;

use crate::core::models::{
    AccountState, GenTimings, LastTransactionId, Transaction, TransactionId, TransactionsBatchInfo,
};
use crate::transport::models::TransactionFull;
use crate::transport::Transport;

pub fn convert_transactions(
    transactions: Vec<TransactionFull>,
) -> impl Iterator<Item = Transaction> + DoubleEndedIterator {
    transactions
        .into_iter()
        .filter_map(|transaction| Transaction::try_from((transaction.hash, transaction.data)).ok())
}

pub fn request_transactions<'a>(
    transport: &'a dyn Transport,
    address: &'a MsgAddressInt,
    from: TransactionId,
    until: Option<&'a TransactionId>,
    initial_count: u8,
    limit: Option<usize>,
) -> impl Stream<Item = NewTransactions> + 'a {
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

pub struct ParsedBlock {
    pub current_utime: u32,
    pub data: Option<(AccountState, Option<NewTransactions>)>,
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

pub fn parse_block(
    address: &MsgAddressInt,
    account_state: &AccountState,
    block: &ton_block::Block,
) -> Result<ParsedBlock> {
    use ton_block::{Deserializable, HashmapAugType};
    use ton_types::HashmapType;

    let info = block
        .info
        .read_struct()
        .map_err(|_| BlockParsingError::InvalidBlockStructure)?;

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

#[derive(thiserror::Error, Debug)]
pub enum BlockParsingError {
    #[error("Invalid block structure")]
    InvalidBlockStructure,
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
