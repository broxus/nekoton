use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use ed25519_dalek::PublicKey;
use futures_util::{Future, FutureExt, Stream};
use ton_block::{MsgAddressInt, Serializable};

use nekoton_abi::{SignedMessage, UnsignedMessage};
use nekoton_utils::*;

use crate::models::*;
use crate::transport::Transport;

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
    from_lt: u64,
    until_lt: Option<u64>,
    initial_count: u8,
    limit: Option<usize>,
) -> impl Stream<Item = Vec<RawTransaction>> + 'a {
    let count = u8::min(initial_count, transport.info().max_transactions_per_fetch);

    LatestTransactions {
        address,
        until_lt,
        transport,
        fut: Some(transport.get_transactions(address, from_lt, count)),
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
            account_blocks.get_with_aug(&ton_types::UInt256::from_be_bytes(
                &address.address().get_bytestring(0),
            ))
        }) {
        Ok(Some((extra, _))) => extra,
        _ => return Ok(ParsedBlock::empty(info.gen_utime().0)),
    };

    let mut balance = contract_state.balance as i128;
    let mut new_transactions = Vec::new();

    let mut last_lt = contract_state.last_lt;
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

        last_lt = std::cmp::max(last_lt, compute_account_lt(&transaction.data));
        new_transactions.push(transaction);
    }

    let new_contract_state = ContractState {
        last_lt,
        balance: balance as u64,
        last_transaction_id: latest_transaction_id
            .map(LastTransactionId::Exact)
            .or(contract_state.last_transaction_id),
        is_deployed,
        code_hash: contract_state.code_hash, // NOTE: code hash update is not visible
    };

    let new_transactions =
        if let (Some(first), Some(last)) = (new_transactions.first(), new_transactions.last()) {
            Some(TransactionsBatchInfo {
                min_lt: first.data.lt, // transactions in block info are in ascending order
                max_lt: last.data.lt,
                batch_type: TransactionsBatchType::New,
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

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum BlockParsingError {
    #[error("Invalid block structure")]
    InvalidBlockStructure,
}

type NewTransactions = (Vec<RawTransaction>, TransactionsBatchInfo);

struct LatestTransactions<'a> {
    address: &'a MsgAddressInt,
    until_lt: Option<u64>,
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
        if let Some(until_lt) = self.until_lt {
            new_transactions.truncate({
                let mut len = 0;
                for item in new_transactions.iter() {
                    if item.data.lt > until_lt {
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
            || matches!(self.until_lt, Some(until_lt) if last.data.prev_trans_lt <= until_lt)
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
            self.address,
            last.data.prev_trans_lt,
            next_count,
        ));

        // Return result
        Poll::Ready(Some(new_transactions))
    }
}

#[derive(Debug, Copy, Clone)]
pub struct MessageContext {
    pub latest_lt: u64,
    pub created_at: u32,
    pub expire_at: u32,
}

pub trait PendingTransactionsExt {
    fn add_message(
        &mut self,
        target: &MsgAddressInt,
        message: &ton_block::Message,
        ctx: MessageContext,
    ) -> Result<PendingTransaction>;

    fn cancel(&mut self, pending_transaction: &PendingTransaction);
}

impl PendingTransactionsExt for Vec<PendingTransaction> {
    fn add_message(
        &mut self,
        target: &MsgAddressInt,
        message: &ton_block::Message,
        ctx: MessageContext,
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

        let pending_transaction = PendingTransaction {
            message_hash: message.serialize()?.repr_hash(),
            src,
            latest_lt: ctx.latest_lt,
            created_at: ctx.created_at,
            expire_at: ctx.expire_at,
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
    clock: &dyn Clock,
    message: ton_block::Message,
    expiration: Expiration,
    public_key: &PublicKey,
    function: Cow<'static, ton_abi::Function>,
    input: Vec<ton_abi::Token>,
) -> Result<Box<dyn UnsignedMessage>> {
    let time = clock.now_ms_u64();
    let (expire_at, header) = default_headers(time, expiration, public_key);

    let (payload, hash) =
        function.create_unsigned_call(&header, &input, false, true, message.dst())?;

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
    hash: ton_types::UInt256,
    expire_at: ExpireAt,
    message: ton_block::Message,
}

impl UnsignedMessage for LabsUnsignedMessage {
    fn refresh_timeout(&mut self, clock: &dyn Clock) {
        let time = clock.now_ms_u64();

        if !self.expire_at.refresh_from_millis(time) {
            return;
        }

        *self.header.get_mut("time").trust_me() = ton_abi::TokenValue::Time(time);
        *self.header.get_mut("expire").trust_me() = ton_abi::TokenValue::Expire(self.expire_at());

        let (payload, hash) = self
            .function
            .create_unsigned_call(&self.header, &self.input, false, true, self.message.dst())
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
        let payload = ton_abi::Function::fill_sign(
            &self.function.abi_version,
            Some(signature),
            None,
            payload,
        )?;

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
