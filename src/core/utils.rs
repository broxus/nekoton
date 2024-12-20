use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use ed25519_dalek::PublicKey;
use futures_util::{Future, FutureExt, Stream};
use nekoton_abi::{GenTimings, LastTransactionId, TransactionId};
use nekoton_utils::*;
use serde::Deserialize;
use ton_block::{AccountState, Deserializable, MsgAddressInt, Serializable};
use ton_types::{CellType, SliceData, UInt256};

use crate::core::models::*;
#[cfg(feature = "wallet_core")]
use crate::crypto::{SignedMessage, UnsignedMessage};
use crate::transport::models::RawTransaction;
use crate::transport::Transport;

pub fn convert_transactions(
    transactions: Vec<RawTransaction>,
) -> impl DoubleEndedIterator<Item = Transaction> {
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
) -> impl Stream<Item = Result<Vec<RawTransaction>>> + 'a {
    let initial_count = u8::min(initial_count, transport.info().max_transactions_per_fetch);
    let fut = transport.get_transactions(address, from_lt, initial_count);

    LatestTransactions {
        address,
        from_lt,
        until_lt,
        transport,
        fut: Some(fut),
        initial_count,
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
    fn empty(current_utime: u32) -> Self {
        Self {
            current_utime,
            data: None,
        }
    }

    #[inline]
    fn with_data(
        current_utime: u32,
        contract_state: ContractState,
        new_transactions: Option<NewTransactions>,
    ) -> Self {
        Self {
            current_utime,
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
        _ => return Ok(ParsedBlock::empty(info.gen_utime().as_u32())),
    };

    let mut balance = contract_state.balance as i128;
    let mut new_transactions = Vec::new();

    let mut last_lt = contract_state.last_lt;
    let mut latest_transaction_id: Option<TransactionId> = None;
    let mut is_deployed = contract_state.is_deployed;

    for item in account_block.transactions().iter() {
        let result = item.and_then(|(_, value)| {
            let cell = value.into_cell().reference(0)?;
            let hash = cell.repr_hash();

            ton_block::Transaction::construct_from_cell(cell)
                .map(|data| RawTransaction { hash, data })
        });
        let transaction = match result {
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
        gen_timings: GenTimings::Known {
            gen_lt: info.end_lt(),
            gen_utime: info.gen_utime().as_u32(),
        },
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
        info.gen_utime().as_u32(),
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
    from_lt: u64,
    until_lt: Option<u64>,
    transport: &'a dyn Transport,
    fut: Option<TransactionsFut<'a>>,
    initial_count: u8,
    total_fetched: usize,
    limit: Option<usize>,
}

#[cfg(not(feature = "non_threadsafe"))]
type TransactionsFut<'a> = Pin<Box<dyn Future<Output = Result<Vec<RawTransaction>>> + Send + 'a>>;
#[cfg(feature = "non_threadsafe")]
type TransactionsFut<'a> = Pin<Box<dyn Future<Output = Result<Vec<RawTransaction>>> + 'a>>;

impl<'a> Stream for LatestTransactions<'a> {
    type Item = Result<Vec<RawTransaction>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // poll `get_transactions` future
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
                // return error without resetting future
                Err(e) => return Poll::Ready(Some(Err(e))),
            };

            // ensure that transactions are sorted in reverse order (from the latest lt)
            new_transactions.sort_by_key(|tx| std::cmp::Reverse(tx.data.lt));

            // get next lt from the unfiltered response to continue
            // fetching transactions if filter produced empty array
            let next_lt_from_response = match new_transactions.last() {
                Some(last) => last.data.prev_trans_lt,
                // early return on empty response
                None => return Poll::Ready(None),
            };
            let mut possibly_has_more = next_lt_from_response > 0;

            let mut truncated = false;
            if let Some(first_tx) = new_transactions.first() {
                if first_tx.data.lt > self.from_lt {
                    // retain only elements in range (until_lt; from_lt]
                    // NOTE: `until_lt < from_lt`
                    let until_lt = self.until_lt.unwrap_or_default();
                    let range = (until_lt + 1)..=self.from_lt;

                    new_transactions.retain(|item| {
                        possibly_has_more &= item.data.lt > until_lt;
                        range.contains(&item.data.lt)
                    });
                    truncated = true;
                }
            }

            if !truncated {
                if let Some(until_lt) = self.until_lt {
                    if let Some(len) = new_transactions
                        .iter()
                        .position(|tx| tx.data.lt <= until_lt)
                    {
                        new_transactions.truncate(len);
                        possibly_has_more = false;
                    }
                }
            }

            // get batch info
            let last = match new_transactions.last() {
                Some(last) => last,
                None if possibly_has_more => {
                    self.fut = Some(self.transport.get_transactions(
                        self.address,
                        next_lt_from_response,
                        self.initial_count,
                    ));
                    continue;
                }
                None => return Poll::Ready(None),
            };

            // set next batch bound
            self.from_lt = last.data.prev_trans_lt;

            // check if there are no transactions left or all transactions were requested
            if last.data.prev_trans_lt == 0
                || matches!(self.until_lt, Some(until_lt) if last.data.prev_trans_lt <= until_lt)
            {
                return Poll::Ready(Some(Ok(new_transactions)));
            }

            // update counters
            self.total_fetched += new_transactions.len();

            let next_count = match self.limit {
                Some(limit) if self.total_fetched >= limit => {
                    return Poll::Ready(Some(Ok(new_transactions)))
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
            return Poll::Ready(Some(Ok(new_transactions)));
        }
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
        )
        .and_then(ton_types::SliceData::load_builder)?;

        let mut message = self.message.clone();
        message.set_body(payload);

        Ok(SignedMessage {
            message,
            expire_at: self.expire_at(),
        })
    }

    fn sign_with_pruned_payload(
        &self,
        signature: &[u8; ed25519_dalek::SIGNATURE_LENGTH],
        prune_after_depth: u16,
    ) -> Result<SignedMessage> {
        let payload = self.payload.clone();
        let payload = ton_abi::Function::fill_sign(
            &self.function.abi_version,
            Some(signature),
            None,
            payload,
        )?
        .into_cell()?;

        let mut message = self.message.clone();
        message.set_body(prune_deep_cells(&payload, prune_after_depth)?);

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

pub async fn update_library_cell(state: &mut AccountState) -> Result<()> {
    if let AccountState::AccountActive { ref mut state_init } = state {
        if let Some(cell) = &state_init.code {
            if cell.cell_type() == CellType::LibraryReference {
                let mut slice_data = SliceData::load_cell(cell.clone())?;

                // Read Library Cell Tag
                let tag = slice_data.get_next_byte()?;
                assert_eq!(tag, 2);

                // Read Code Hash
                let mut hash = UInt256::default();
                hash.read_from(&mut slice_data)?;

                let cell = download_lib(hash).await?;
                state_init.set_code(cell);
            }
        }
    }

    Ok(())
}

async fn download_lib(hash: UInt256) -> Result<ton_types::Cell> {
    static URL: &str = "https://dton.io/graphql/graphql";

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );

    let client = reqwest::ClientBuilder::new()
        .default_headers(headers)
        .build()?;

    let query = serde_json::json!({
        "query": format!("{{
        get_lib(
            lib_hash: \"{}\"
        )
    }}", hash.to_hex_string().to_uppercase())
    })
    .to_string();

    let response = client.post(URL).body(query).send().await?;

    #[derive(Deserialize)]
    struct GqlResponse {
        data: Data,
    }

    #[derive(Deserialize)]
    struct Data {
        get_lib: String,
    }

    let parsed: GqlResponse = response.json().await?;

    let bytes = base64::decode(parsed.data.get_lib)?;
    let cell = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())?;

    Ok(cell)
}
