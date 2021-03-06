use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use ed25519_dalek::PublicKey;
use futures::{Future, FutureExt, Stream};
use ton_block::{MsgAddressInt, Serializable};

use crate::core::models::*;
use crate::crypto::{SignedMessage, UnsignedMessage};
use crate::transport::models::RawTransaction;
use crate::transport::Transport;
use crate::utils::*;

pub fn convert_transactions(
    transactions: Vec<RawTransaction>,
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
) -> impl Stream<Item = Vec<RawTransaction>> + 'a {
    let count = u8::min(initial_count, transport.info().max_transactions_per_fetch);

    LatestTransactions {
        address,
        until,
        transport,
        fut: Some(transport.get_transactions(address.clone(), from, count)),
        total_fetched: 0,
        limit,
    }
}

#[derive(Debug)]
pub struct ParsedBlock {
    pub current_utime: u32,
    pub data: Option<(ContractState, Option<NewTransactions>)>,
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
        contract_state: ContractState,
        new_transactions: Option<NewTransactions>,
    ) -> Self {
        Self {
            current_utime: utime,
            data: Some((contract_state, new_transactions)),
        }
    }
}

pub fn parse_block(
    address: &MsgAddressInt,
    contract_state: &ContractState,
    block: &ton_block::Block,
) -> Result<ParsedBlock> {
    use ton_block::{Deserializable, HashmapAugType};
    use ton_types::HashmapType;

    let info = block
        .info
        .read_struct()
        .map_err(|_| BlockParsingError::InvalidBlockStructure)?;

    let account_block = match block
        .extra
        .read_struct()
        .and_then(|extra| extra.read_account_blocks())
        .and_then(|account_blocks| {
            account_blocks.get_with_aug(&address.address().get_bytestring(0).into())
        }) {
        Ok(Some((extra, _))) => extra,
        _ => return Ok(ParsedBlock::empty(info.gen_utime().0)),
    };

    let mut balance = contract_state.balance as i64;
    let mut new_transactions = Vec::new();

    let mut latest_transaction_id: Option<TransactionId> = None;
    let mut is_deployed = contract_state.is_deployed;

    for item in account_block.transactions().iter() {
        let transaction = match item.and_then(|(_, value)| {
            let cell = value.into_cell().reference(0)?;
            let hash = cell.repr_hash();

            ton_block::Transaction::construct_from_cell(cell)
                .map(|data| RawTransaction { hash, data })
        }) {
            Ok(transaction) => transaction,
            Err(_) => continue,
        };

        balance += compute_balance_change(&transaction.data);

        is_deployed = transaction.data.end_status == ton_block::AccountStatus::AccStateActive;

        if matches!(&latest_transaction_id, Some(id) if transaction.data.lt > id.lt) {
            latest_transaction_id = Some(TransactionId {
                lt: transaction.data.lt,
                hash: transaction.hash,
            })
        }

        new_transactions.push(transaction)
    }

    let new_contract_state = ContractState {
        balance: balance as u64,
        gen_timings: GenTimings::Known {
            gen_lt: info.end_lt(),
            gen_utime: info.gen_utime().0,
        },
        last_transaction_id: latest_transaction_id
            .map(LastTransactionId::Exact)
            .or(contract_state.last_transaction_id),
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
        new_contract_state,
        new_transactions,
    ))
}

pub fn compute_balance_change(transaction: &ton_block::Transaction) -> i64 {
    let mut diff = 0;

    if let Some(in_msg) = transaction
        .in_msg
        .as_ref()
        .and_then(|data| data.read_struct().ok())
    {
        if let ton_block::CommonMsgInfo::IntMsgInfo(header) = in_msg.header() {
            diff += header.value.grams.0 as i64;
        }
    }

    let _ = transaction.out_msgs.iterate(|out_msg| {
        if let ton_block::CommonMsgInfo::IntMsgInfo(header) = out_msg.0.header() {
            diff -= header.value.grams.0 as i64;
        }
        Ok(true)
    });

    if let Ok(ton_block::TransactionDescr::Ordinary(description)) =
        transaction.description.read_struct()
    {
        diff -= compute_total_transaction_fees(transaction, &description) as i64;
    }

    diff
}

/// Calculate total transaction fee which is charged from the account
pub fn compute_total_transaction_fees(
    transaction: &ton_block::Transaction,
    description: &ton_block::TransactionDescrOrdinary,
) -> u64 {
    let mut total_fees = transaction.total_fees.grams.0;
    if let Some(phase) = &description.action {
        total_fees += phase
            .total_fwd_fees
            .as_ref()
            .map(|grams| grams.0)
            .unwrap_or_default();
        total_fees -= phase
            .total_action_fees
            .as_ref()
            .map(|grams| grams.0)
            .unwrap_or_default();
    };
    total_fees as u64
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum BlockParsingError {
    #[error("Invalid block structure")]
    InvalidBlockStructure,
}

type NewTransactions = (Vec<RawTransaction>, TransactionsBatchInfo);

struct LatestTransactions<'a> {
    address: &'a MsgAddressInt,
    until: Option<&'a TransactionId>,
    transport: &'a dyn Transport,
    fut: Option<TransactionsFut<'a>>,
    total_fetched: usize,
    limit: Option<usize>,
}

type TransactionsFut<'a> = Pin<Box<dyn Future<Output = Result<Vec<RawTransaction>>> + Send + 'a>>;

impl<'a> Stream for LatestTransactions<'a> {
    type Item = Vec<RawTransaction>;

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
        let last = match new_transactions.last() {
            Some(last) => last,
            None => return Poll::Ready(None),
        };

        // check if there are no transactions left or all transactions were requested
        if last.data.prev_trans_lt == 0
            || matches!(self.until, Some(until) if last.data.prev_trans_lt <= until.lt)
        {
            return Poll::Ready(Some(new_transactions));
        }

        // update counters
        self.total_fetched += new_transactions.len();

        let next_count = match self.limit {
            Some(limit) if self.total_fetched >= limit => {
                return Poll::Ready(Some(new_transactions))
            }
            Some(limit) => usize::min(
                limit - self.total_fetched,
                self.transport.info().max_transactions_per_fetch as usize,
            ) as u8,
            None => self.transport.info().max_transactions_per_fetch,
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
        Poll::Ready(Some(new_transactions))
    }
}

pub trait PendingTransactionsExt {
    fn add_message(
        &mut self,
        target: &MsgAddressInt,
        message: &ton_block::Message,
        expire_at: u32,
    ) -> Result<PendingTransaction>;

    fn cancel(&mut self, pending_transaction: &PendingTransaction);
}

impl PendingTransactionsExt for Vec<PendingTransaction> {
    fn add_message(
        &mut self,
        target: &MsgAddressInt,
        message: &ton_block::Message,
        expire_at: u32,
    ) -> Result<PendingTransaction> {
        let src = match message.header() {
            ton_block::CommonMsgInfo::ExtInMsgInfo(header) => {
                if &header.dst == target {
                    None
                } else {
                    return Err(AccountSubscriptionError::InvalidMessageDestination.into());
                }
            }
            _ => return Err(AccountSubscriptionError::InvalidMessageType.into()),
        };

        let body_hash = message
            .body()
            .map(|body| body.into_cell().repr_hash())
            .unwrap_or_default();

        let pending_transaction = PendingTransaction {
            message_hash: message.serialize().convert()?.repr_hash(),
            src,
            body_hash,
            expire_at,
        };

        self.push(pending_transaction.clone());
        Ok(pending_transaction)
    }

    fn cancel(&mut self, pending_transaction: &PendingTransaction) {
        if let Some(i) = self.iter().position(|item| item.eq(pending_transaction)) {
            self.remove(i);
        }
    }
}

pub fn make_labs_unsigned_message(
    message: ton_block::Message,
    expiration: Expiration,
    public_key: &PublicKey,
    function: Cow<'static, ton_abi::Function>,
    input: Vec<ton_abi::Token>,
) -> Result<Box<dyn UnsignedMessage>> {
    let time = chrono::Utc::now().timestamp_millis() as u64;
    let (expire_at, header) = default_headers(time, expiration, public_key);

    let (payload, hash) = function
        .create_unsigned_call(&header, &input, false, true)
        .convert()?;

    Ok(Box::new(LabsUnsignedMessage {
        function,
        header,
        input,
        payload,
        hash,
        expire_at,
        message,
    }))
}

#[derive(Clone)]
struct LabsUnsignedMessage {
    function: Cow<'static, ton_abi::Function>,
    header: HeadersMap,
    input: Vec<ton_abi::Token>,
    payload: ton_types::BuilderData,
    hash: Vec<u8>,
    expire_at: ExpireAt,
    message: ton_block::Message,
}

impl UnsignedMessage for LabsUnsignedMessage {
    fn refresh_timeout(&mut self) {
        let time = chrono::Utc::now().timestamp_millis() as u64;

        if !self.expire_at.refresh_from_millis(time) {
            return;
        }

        *self.header.get_mut("time").trust_me() = ton_abi::TokenValue::Time(time);
        *self.header.get_mut("expire").trust_me() = ton_abi::TokenValue::Expire(self.expire_at());

        let (payload, hash) = self
            .function
            .create_unsigned_call(&self.header, &self.input, false, true)
            .trust_me();
        self.payload = payload;
        self.hash = hash;
    }

    fn expire_at(&self) -> u32 {
        self.expire_at.timestamp
    }

    fn hash(&self) -> &[u8] {
        self.hash.as_slice()
    }

    fn sign(&self, signature: &[u8; ed25519_dalek::SIGNATURE_LENGTH]) -> Result<SignedMessage> {
        let payload = self.payload.clone();
        let payload = ton_abi::Function::fill_sign(2, Some(signature), None, payload).convert()?;

        let mut message = self.message.clone();
        message.set_body(payload.into());

        Ok(SignedMessage {
            message,
            expire_at: self.expire_at(),
        })
    }
}

pub fn default_headers(
    time: u64,
    expiration: Expiration,
    public_key: &PublicKey,
) -> (ExpireAt, HeadersMap) {
    let expire_at = ExpireAt::new_from_millis(expiration, time);

    let mut header = HashMap::with_capacity(3);
    header.insert("time".to_string(), ton_abi::TokenValue::Time(time));
    header.insert(
        "expire".to_string(),
        ton_abi::TokenValue::Expire(expire_at.timestamp),
    );
    header.insert(
        "pubkey".to_string(),
        ton_abi::TokenValue::PublicKey(Some(*public_key)),
    );

    (expire_at, header)
}

type HeadersMap = HashMap<String, ton_abi::TokenValue>;
