use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use anyhow::Result;
use num_traits::ToPrimitive;
use smallvec::smallvec;
use ton_abi::{Function, Param, Token, TokenValue};
use ton_block::{
    Account, AccountStuff, Deserializable, GetRepresentationHash, MsgAddrStd, MsgAddressInt,
    Serializable,
};
use ton_executor::{BlockchainConfig, OrdinaryTransactionExecutor, TransactionExecutor};
use ton_types::{SliceData, UInt256};

#[cfg(feature = "derive")]
pub use {
    nekoton_derive::{
        KnownParamType, KnownParamTypePlain, PackAbi, PackAbiPlain, UnpackAbi, UnpackAbiPlain,
    },
    num_bigint, num_traits,
};

use nekoton_utils::*;

pub use self::abi_helpers::*;
pub use self::code_salt::*;
pub use self::event_builder::*;
pub use self::function_builder::*;
pub use self::known_param_type::*;
pub use self::message_builder::*;
pub use self::models::*;
pub use self::token_packer::*;
pub use self::token_unpacker::*;
pub use self::tokens_json::*;
pub use transaction_parser::TransactionParser;

mod abi_helpers;
mod code_salt;
mod event_builder;
mod function_builder;
mod known_param_type;
mod message_builder;
mod models;
mod token_packer;
mod token_unpacker;
mod tokens_json;
pub mod transaction_parser;
mod tvm;

const TON_ABI_VERSION: ton_abi::contract::AbiVersion = ton_abi::contract::ABI_VERSION_2_0;

pub fn read_function_id(data: &SliceData) -> Result<u32> {
    let mut value: u32 = 0;
    for i in 0..4 {
        value |= (data.get_byte(8 * i)? as u32) << (8 * (3 - i));
    }
    Ok(value)
}

pub fn read_input_function_id(
    contract: &ton_abi::Contract,
    mut body: SliceData,
    internal: bool,
) -> Result<u32> {
    if !internal {
        // Skip optional signature
        if body.get_next_bit()? {
            body.move_by(ed25519_dalek::SIGNATURE_LENGTH * 8)?;
        }

        // Skip headers
        for header in &contract.header {
            match header.kind {
                ton_abi::ParamType::PublicKey => {
                    if body.get_next_bit()? {
                        body.move_by(ed25519_dalek::PUBLIC_KEY_LENGTH * 8)?;
                    }
                }
                ton_abi::ParamType::Time => body.move_by(64)?,
                ton_abi::ParamType::Expire => body.move_by(32)?,
                _ => return Err(AbiError::UnsupportedHeader.into()),
            }
        }
    }

    read_function_id(&body)
}

pub fn guess_method_by_input<'a>(
    contract: &'a ton_abi::Contract,
    message_body: &SliceData,
    method: &MethodName,
    internal: bool,
) -> Result<Option<&'a ton_abi::Function>> {
    let names = match method {
        MethodName::Known(name) => return Ok(Some(contract.function(name)?)),
        MethodName::GuessInRange(names) => Some(names),
        MethodName::Guess => None,
    };

    let input_id = match read_input_function_id(contract, message_body.clone(), internal) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };

    let mut method = None;
    match names {
        Some(names) => {
            for name in names {
                let function = contract.function(name)?;
                if function.input_id == input_id {
                    method = Some(function);
                    break;
                }
            }
        }
        None => {
            for function in contract.functions.values() {
                if function.input_id == input_id {
                    method = Some(function);
                    break;
                }
            }
        }
    }
    Ok(method)
}

pub enum MethodName {
    Known(String),
    GuessInRange(Vec<String>),
    Guess,
}

/// Tries to parse text as boc, encodes as comment otherwise
pub fn create_boc_or_comment_payload(data: &str) -> Result<SliceData> {
    create_boc_payload(data.trim())
        .map(Ok)
        .unwrap_or_else(|_| create_comment_payload(data))
}

/// Creates slice data with string, encoded as comment
pub fn create_comment_payload(comment: &str) -> Result<SliceData> {
    ton_abi::TokenValue::pack_values_into_chain(
        &[
            0u32.token_value().unnamed(),
            comment.token_value().unnamed(),
        ],
        Vec::new(),
        &TON_ABI_VERSION,
    )
    .map(SliceData::from)
}

pub fn parse_comment_payload(mut payload: SliceData) -> Option<String> {
    if payload.get_next_u32().ok()? != 0 {
        return None;
    }

    let mut cell = payload.checked_drain_reference().ok()?;

    let mut data = Vec::new();
    loop {
        data.extend_from_slice(cell.data());
        data.pop();
        cell = match cell.reference(0) {
            Ok(cell) => cell.clone(),
            Err(_) => break,
        };
    }

    String::from_utf8(data).ok()
}

/// Creates slice data from base64 encoded boc
pub fn create_boc_payload(cell: &str) -> Result<SliceData> {
    let bytes = base64::decode(&cell)?;
    let cell = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())
        .map_err(|_| UnpackerError::InvalidAbi)?;
    Ok(SliceData::from(cell))
}

pub fn pack_into_cell(tokens: &[ton_abi::Token]) -> Result<ton_types::Cell> {
    let cells = Vec::new();
    ton_abi::TokenValue::pack_values_into_chain(tokens, cells, &TON_ABI_VERSION)
        .and_then(|x| x.into_cell())
}

pub fn unpack_from_cell(
    params: &[Param],
    mut cursor: SliceData,
    allow_partial: bool,
) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();

    for param in params {
        let last = Some(param) == params.last();
        let (token_value, new_cursor) =
            TokenValue::read_from(&param.kind, cursor, last, &TON_ABI_VERSION, allow_partial)?;

        cursor = new_cursor;
        tokens.push(Token {
            name: param.name.clone(),
            value: token_value,
        });
    }

    if !allow_partial && (cursor.remaining_references() != 0 || cursor.remaining_bits() != 0) {
        Err(AbiError::IncompleteDeserialization(cursor).into())
    } else {
        Ok(tokens)
    }
}

pub fn extract_public_key(
    account: &AccountStuff,
) -> Result<ed25519_dalek::PublicKey, ExtractionError> {
    let state_init = match &account.storage.state {
        ton_block::AccountState::AccountActive { state_init, .. } => state_init,
        _ => return Err(ExtractionError::AccountIsNotActive),
    };
    let mut data: SliceData = match &state_init.data {
        Some(data) => data.into(),
        None => return Err(ExtractionError::AccountDataNotFound),
    };
    let data = data
        .get_next_bytes(32)
        .map_err(|_| ExtractionError::CellUnderflow)?;

    Ok(ed25519_dalek::PublicKey::from_bytes(&data).trust_me())
}

pub fn get_state_init_hash(
    mut state_init: ton_block::StateInit,
    contract: &ton_abi::Contract,
    public_key: &Option<ed25519_dalek::PublicKey>,
    init_data: Vec<ton_abi::Token>,
) -> Result<UInt256> {
    state_init.data = if let Some(data) = state_init.data.take() {
        Some(insert_state_init_data(contract, data.into(), public_key, init_data)?.into_cell())
    } else {
        None
    };
    state_init.hash()
}

pub fn insert_state_init_data(
    contract: &ton_abi::Contract,
    data: SliceData,
    public_key: &Option<ed25519_dalek::PublicKey>,
    tokens: Vec<ton_abi::Token>,
) -> Result<SliceData> {
    #[derive(thiserror::Error, Debug)]
    enum InitDataError {
        #[error("Token not found: {}", .0)]
        TokenNotFound(String),
        #[error("Token param type mismatch")]
        TokenParamTypeMismatch,
    }

    let mut map = ton_types::HashmapE::with_hashmap(
        ton_abi::Contract::DATA_MAP_KEYLEN,
        data.reference_opt(0),
    );

    if let Some(public_key) = public_key {
        map.set_builder(
            0u64.write_to_new_cell().trust_me().into(),
            ton_types::BuilderData::new()
                .append_raw(public_key.as_bytes(), 256)
                .trust_me(),
        )?;
    }

    if !contract.data.is_empty() {
        let tokens = tokens
            .into_iter()
            .map(|token| (token.name, token.value))
            .collect::<HashMap<_, _>>();

        for (param_name, param) in &contract.data {
            let token = tokens
                .get(param_name)
                .ok_or_else(|| InitDataError::TokenNotFound(param_name.clone()))?;
            if !token.type_check(&param.value.kind) {
                return Err(InitDataError::TokenParamTypeMismatch.into());
            }

            let builder = token.pack_into_chain(&TON_ABI_VERSION)?;
            map.set_builder(param.key.write_to_new_cell().trust_me().into(), &builder)?;
        }
    }

    map.write_to_new_cell().map(From::from)
}

pub fn decode_input<'a>(
    contract: &'a ton_abi::Contract,
    message_body: SliceData,
    method: &MethodName,
    internal: bool,
) -> Result<Option<(&'a ton_abi::Function, Vec<Token>)>> {
    let function = match guess_method_by_input(contract, &message_body, method, internal)? {
        Some(function) => function,
        None => return Ok(None),
    };

    let input = function.decode_input(message_body, internal)?;
    Ok(Some((function, input)))
}

pub fn decode_output<'a>(
    contract: &'a ton_abi::Contract,
    message_body: SliceData,
    method: &MethodName,
) -> Result<Option<(&'a ton_abi::Function, Vec<Token>)>> {
    let output_id = match read_function_id(&message_body) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };

    let function = match method {
        MethodName::Known(name) => Some(contract.function(name)?),
        MethodName::GuessInRange(names) => {
            let mut function = None;
            for name in names {
                let entry = contract.function(name)?;
                if entry.output_id == output_id {
                    function = Some(entry);
                    break;
                }
            }
            function
        }
        MethodName::Guess => {
            let mut function = None;
            for entry in contract.functions.values() {
                if entry.output_id == output_id {
                    function = Some(entry);
                    break;
                }
            }
            function
        }
    };

    let function = match function {
        Some(function) => function,
        None => return Ok(None),
    };

    let output = function.decode_output(message_body, true)?;
    Ok(Some((function, output)))
}

pub fn decode_event<'a>(
    contract: &'a ton_abi::Contract,
    message_body: SliceData,
    name: &MethodName,
) -> Result<Option<(&'a ton_abi::Event, Vec<ton_abi::Token>)>> {
    let events = &contract.events;
    let event_id = match read_function_id(&message_body) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };

    let event = match name {
        MethodName::Known(name) => events.get(name),
        MethodName::GuessInRange(names) => {
            let mut event = None;
            for name in names {
                let entry = match events.get(name) {
                    Some(event) => event,
                    None => continue,
                };
                if entry.id == event_id {
                    event = Some(entry);
                    break;
                }
            }
            event
        }
        MethodName::Guess => {
            let mut event = None;
            for entry in events.values() {
                if entry.id == event_id {
                    event = Some(entry);
                    break;
                }
            }
            event
        }
    };

    let event = match event {
        Some(event) => event,
        None => return Ok(None),
    };

    let data = event.decode_input(message_body)?;
    Ok(Some((event, data)))
}

pub fn unpack_headers<T>(body: &SliceData) -> Result<(T::Output, SliceData)>
where
    T: UnpackHeader,
{
    let mut body = body.clone();
    let output = T::unpack_header(&mut body)?;
    Ok((output, body))
}

macro_rules! impl_unpack_header {
    ($($header:ident),+) => {
        impl UnpackHeader for ($($header),*) {
            type Output = ($(<$header as UnpackHeader>::Output),+);

            fn unpack_header(body: &mut SliceData) -> Result<Self::Output> {
                Ok(($($header::unpack_header(body)?),+))
            }
        }
    }
}

impl_unpack_header!(PubkeyHeader, TimeHeader, ExpireHeader);
impl_unpack_header!(TimeHeader, ExpireHeader);

pub trait UnpackHeader {
    type Output;
    fn unpack_header(body: &mut SliceData) -> Result<Self::Output>;
}

pub struct PubkeyHeader;

impl UnpackHeader for PubkeyHeader {
    type Output = Option<UInt256>;

    fn unpack_header(body: &mut SliceData) -> Result<Self::Output> {
        if body.get_next_bit()? {
            body.move_by(ed25519_dalek::SIGNATURE_LENGTH * 8)?;
        }
        if body.get_next_bit()? {
            let data = body.get_next_bits(256)?;
            Ok(Some(UInt256::from_be_bytes(&data)))
        } else {
            Ok(None)
        }
    }
}

pub struct TimeHeader;

impl UnpackHeader for TimeHeader {
    type Output = u64;

    fn unpack_header(body: &mut SliceData) -> Result<Self::Output> {
        body.get_next_u64()
    }
}

pub struct ExpireHeader;

impl UnpackHeader for ExpireHeader {
    type Output = u32;

    fn unpack_header(body: &mut SliceData) -> Result<Self::Output> {
        body.get_next_u32()
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum ExtractionError {
    #[error("Account is not active")]
    AccountIsNotActive,
    #[error("Account data not found")]
    AccountDataNotFound,
    #[error("Cell underflow")]
    CellUnderflow,
}

pub fn code_to_tvc(code: ton_types::Cell) -> Result<ton_block::StateInit> {
    let pubkey_vec = smallvec![0; 32];
    let pubkey_len = pubkey_vec.len() * 8;
    let value = ton_types::BuilderData::with_raw(pubkey_vec, pubkey_len).unwrap_or_default();

    let mut init_data = ton_types::HashmapE::with_bit_len(ton_abi::Contract::DATA_MAP_KEYLEN);
    init_data.set(0u64.write_to_new_cell().unwrap().into(), &value.into())?;

    let data = init_data
        .write_to_new_cell()
        .and_then(|data| data.into_cell())?;

    Ok(ton_block::StateInit {
        code: Some(code),
        data: Some(data),
        ..Default::default()
    })
}

#[derive(Copy, Clone)]
pub struct ExecutionContext<'a> {
    pub clock: &'a dyn Clock,
    pub account_stuff: &'a AccountStuff,
}

impl<'a> ExecutionContext<'a> {
    pub fn run_local(&self, function: &Function, input: &[Token]) -> Result<ExecutionOutput> {
        function.run_local(self.clock, self.account_stuff.clone(), input)
    }

    pub fn run_local_responsible(
        &self,
        function: &Function,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        function.run_local_responsible(self.clock, self.account_stuff.clone(), input)
    }
}

pub trait FunctionExt {
    fn parse(&self, tx: &ton_block::Transaction) -> Result<Vec<Token>>;

    fn run_local(
        &self,
        clock: &dyn Clock,
        account_stuff: AccountStuff,
        input: &[Token],
    ) -> Result<ExecutionOutput>;

    fn run_local_responsible(
        &self,
        clock: &dyn Clock,
        account_stuff: AccountStuff,
        input: &[Token],
    ) -> Result<ExecutionOutput>;
}

impl<T> FunctionExt for &T
where
    T: FunctionExt,
{
    fn parse(&self, tx: &ton_block::Transaction) -> Result<Vec<Token>> {
        T::parse(self, tx)
    }

    fn run_local(
        &self,
        clock: &dyn Clock,
        account_stuff: AccountStuff,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        T::run_local(self, clock, account_stuff, input)
    }

    fn run_local_responsible(
        &self,
        clock: &dyn Clock,
        account_stuff: AccountStuff,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        T::run_local_responsible(self, clock, account_stuff, input)
    }
}

impl FunctionExt for Function {
    fn parse(&self, tx: &ton_block::Transaction) -> Result<Vec<Token>> {
        let abi = FunctionAbi::new(self);
        abi.parse(tx)
    }

    fn run_local(
        &self,
        clock: &dyn Clock,
        mut account_stuff: AccountStuff,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        FunctionAbi::new(self).run_local(clock, &mut account_stuff, input)
    }

    fn run_local_responsible(
        &self,
        clock: &dyn Clock,
        mut account_stuff: AccountStuff,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        account_stuff.storage.balance.grams.0 = 100_000_000_000_000; // 100 000 TON
        FunctionAbi::new(self).run_local_responsible(clock, &mut account_stuff, input)
    }
}

struct FunctionAbi<'a> {
    abi: &'a Function,
}

impl<'a> FunctionAbi<'a> {
    fn new(abi: &'a Function) -> Self {
        Self { abi }
    }

    fn parse(&self, tx: &ton_block::Transaction) -> Result<Vec<Token>> {
        let messages = parse_transaction_messages(tx)?;
        process_out_messages(&*messages, self.abi)
    }

    fn run_local(
        &self,
        clock: &dyn Clock,
        account_stuff: &mut AccountStuff,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        let mut msg =
            ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
                dst: account_stuff.addr.clone(),
                ..Default::default()
            });

        let BlockStats {
            gen_utime, gen_lt, ..
        } = get_block_stats(clock, None, account_stuff.storage.last_trans_lt);

        msg.set_body(
            self.abi
                .encode_run_local_input(gen_utime as u64 * 1000, input)?
                .into(),
        );

        let tvm::ActionPhaseOutput {
            messages,
            exit_code: result_code,
        } = tvm::call_msg(gen_utime, gen_lt, account_stuff, &msg)?;

        let tokens = messages
            .map(|messages| process_out_messages(&messages, self.abi))
            .transpose()?;

        Ok(ExecutionOutput {
            tokens,
            result_code,
        })
    }

    fn run_local_responsible(
        &self,
        clock: &dyn Clock,
        account_stuff: &mut AccountStuff,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        let function = self.abi;

        let answer_id = match input.first().map(|token| &token.value) {
            Some(TokenValue::Uint(ton_abi::Uint { number, size: 32 })) => {
                number.to_u32().ok_or(AbiError::AnswerIdNotFound)?
            }
            _ => return Err(AbiError::AnswerIdNotFound.into()),
        };

        let mut msg = ton_block::Message::with_int_header(ton_block::InternalMessageHeader {
            src: ton_block::MsgAddressIntOrNone::Some(account_stuff.addr.clone()),
            dst: account_stuff.addr.clone(),
            ..Default::default()
        });

        let BlockStats {
            gen_utime, gen_lt, ..
        } = get_block_stats(clock, None, account_stuff.storage.last_trans_lt);

        msg.set_body(function.encode_internal_input(input)?.into());

        let tvm::ActionPhaseOutput {
            messages,
            exit_code: result_code,
        } = tvm::call_msg(gen_utime, gen_lt, account_stuff, &msg)?;

        let tokens = messages
            .map(|messages| {
                let mut output = None;

                for msg in messages {
                    if !matches!(msg.header(), ton_block::CommonMsgInfo::IntMsgInfo(_)) {
                        continue;
                    }

                    let mut body = match msg.body() {
                        Some(body) => body,
                        None => continue,
                    };

                    if !matches!(
                        body.get_next_u32(),
                        Ok(target_answer_id) if target_answer_id == answer_id
                    ) {
                        continue;
                    }

                    if let Ok(tokens) = TokenValue::decode_params(
                        function.output_params(),
                        body,
                        &function.abi_version,
                        false,
                    ) {
                        output = Some(tokens);
                        break;
                    }
                }

                match output {
                    Some(a) => Ok(a),
                    None if !function.has_output() => Ok(Default::default()),
                    None => Err(AbiError::NoMessagesProduced),
                }
            })
            .transpose()?;

        Ok(ExecutionOutput {
            tokens,
            result_code,
        })
    }
}

#[derive(Debug)]
pub struct ExecutionOutput {
    pub tokens: Option<Vec<Token>>,
    pub result_code: i32,
}

pub fn process_out_messages(
    messages: &[ton_block::Message],
    abi_function: &Function,
) -> Result<Vec<Token>> {
    let mut output = None;

    for msg in messages {
        if !matches!(msg.header(), ton_block::CommonMsgInfo::ExtOutMsgInfo(_)) {
            continue;
        }

        let body = msg.body().ok_or(AbiError::InvalidOutputMessage)?;

        if abi_function.is_my_output_message(body.clone(), false)? {
            let tokens = abi_function.decode_output(body, false)?;

            output = Some(tokens);
            break;
        }
    }

    match output {
        Some(a) => Ok(a),
        None if !abi_function.has_output() => Ok(Default::default()),
        None => Err(AbiError::NoMessagesProduced.into()),
    }
}

pub fn process_raw_outputs(
    ext_out_msg_bodies: &[SliceData],
    abi_function: &Function,
) -> Result<Vec<Token>> {
    let mut output = None;

    for body in ext_out_msg_bodies {
        let function_id = read_function_id(body).map_err(|_| AbiError::InvalidOutputMessage)?;
        if abi_function.output_id != function_id {
            continue;
        }

        output = Some(abi_function.decode_output(body.clone(), false)?);
        break;
    }

    match output {
        Some(a) => Ok(a),
        None if !abi_function.has_output() => Ok(Default::default()),
        None => Err(AbiError::NoMessagesProduced.into()),
    }
}

pub fn parse_transaction_messages(
    transaction: &ton_block::Transaction,
) -> Result<Vec<ton_block::Message>> {
    let mut messages = Vec::new();
    transaction.out_msgs.iterate_slices(|slice| {
        if let Ok(message) = slice
            .reference(0)
            .and_then(ton_block::Message::construct_from_cell)
        {
            messages.push(message);
        }
        Ok(true)
    })?;
    Ok(messages)
}

#[derive(thiserror::Error, Debug)]
enum AbiError {
    #[error("Invalid output message")]
    InvalidOutputMessage,
    #[error("No external output messages")]
    NoMessagesProduced,
    #[error("Incomplete Deserialization")]
    IncompleteDeserialization(SliceData),
    #[error("Unsupported header")]
    UnsupportedHeader,
    #[error("Answer id not found")]
    AnswerIdNotFound,
}

pub struct Executor {
    config: BlockchainConfig,
    account: Account,
    block_utime: u32,
    block_lt: u64,
    last_transaction_lt: Arc<AtomicU64>,
    disable_signature_check: bool,
}

struct BlockStats {
    gen_utime: u32,
    gen_lt: u64,
}

fn get_block_stats(
    clock: &dyn Clock,
    timings: Option<GenTimings>,
    last_trans_lt: u64,
) -> BlockStats {
    // Additional estimated logical time offset for the latest transaction id
    pub const UNKNOWN_TRANSACTION_LT_OFFSET: u64 = 10;

    match timings {
        Some(GenTimings::Known { gen_lt, gen_utime }) => BlockStats { gen_utime, gen_lt },
        _ => BlockStats {
            gen_utime: clock.now_sec_u64() as u32,
            gen_lt: last_trans_lt + UNKNOWN_TRANSACTION_LT_OFFSET,
        },
    }
}

impl Executor {
    pub fn new(
        clock: &dyn Clock,
        config: BlockchainConfig,
        account_stuff: AccountStuff,
        _timings: GenTimings,
    ) -> Self {
        let last_trans_lt = account_stuff.storage.last_trans_lt;

        let BlockStats { gen_utime, gen_lt } = get_block_stats(clock, None, last_trans_lt);

        Self {
            config,
            account: Account::Account(account_stuff),
            block_utime: gen_utime,
            block_lt: gen_lt,
            last_transaction_lt: Arc::new(AtomicU64::new(last_trans_lt)),
            disable_signature_check: false,
        }
    }

    pub fn disable_signature_check(&mut self) -> &mut Self {
        self.disable_signature_check = true;
        self
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    pub fn run(&mut self, message: &ton_block::Message) -> Result<ton_block::Transaction> {
        let mut executor = OrdinaryTransactionExecutor::new(self.config.clone());
        executor.set_signature_check_disabled(self.disable_signature_check);

        let params = ton_executor::ExecuteParams {
            block_unixtime: self.block_utime,
            block_lt: self.block_lt,
            last_tr_lt: self.last_transaction_lt.clone(),
            ..Default::default()
        };

        let mut account_root = self.account.serialize()?;
        executor.execute_with_libs_and_params(Some(message), &mut account_root, params)
    }
}

/// Alias for TokenValue::Optional
///
/// NOTE: inner value can be in the same cell or in reference
#[derive(Debug)]
pub struct Maybe<T>(pub Option<T>);

/// TokenValue::Optional which always store its value in the cell
#[derive(Debug)]
pub struct MaybeRef<T>(pub Option<T>);

pub trait StandaloneToken {}
impl StandaloneToken for i16 {}
impl StandaloneToken for u16 {}
impl StandaloneToken for i32 {}
impl StandaloneToken for u32 {}
impl StandaloneToken for i64 {}
impl StandaloneToken for u64 {}
impl StandaloneToken for i128 {}
impl StandaloneToken for u128 {}
impl StandaloneToken for bool {}
impl StandaloneToken for MsgAddressInt {}
impl StandaloneToken for MsgAddrStd {}
impl StandaloneToken for UInt256 {}
impl StandaloneToken for Vec<u8> {}
impl StandaloneToken for TokenValue {}
impl StandaloneToken for ton_block::Grams {}
impl StandaloneToken for ton_types::Cell {}
impl<T> StandaloneToken for Maybe<T> {}
impl<T> StandaloneToken for MaybeRef<T> {}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ton_abi::{Param, ParamType, Uint};
    use ton_block::{Deserializable, Message, Transaction};
    use ton_types::serialize_toc;

    use super::*;

    #[test]
    fn correct_text_payload() {
        let comment = create_boc_or_comment_payload("test").unwrap();
        assert_eq!(parse_comment_payload(comment).unwrap(), "test");

        const BOC: &str = "te6ccgEBAQEABgAACAAABdA=";
        let boc = create_boc_or_comment_payload(BOC).unwrap();
        let target_boc =
            ton_types::deserialize_tree_of_cells(&mut base64::decode(BOC).unwrap().as_slice())
                .unwrap();
        assert!(parse_comment_payload(boc.clone()).is_none());
        assert_eq!(boc.into_cell(), target_boc);
    }

    #[test]
    fn test_run_local() {
        let contract = r#####"{
            "ABI version": 2,
            "header": ["pubkey", "time", "expire"],
            "functions": [
                {
                    "name": "getCustodians",
                    "inputs": [],
                    "outputs": [
                        {"components":[{"name":"index","type":"uint8"},{"name":"pubkey","type":"uint256"}],"name":"custodians","type":"tuple[]"}
                    ]
                },
                {
                    "name": "submitTransaction",
                    "inputs": [
                        {"name":"dest","type":"address"},
                        {"name":"value","type":"uint128"},
                        {"name":"bounce","type":"bool"},
                        {"name":"allBalance","type":"bool"},
                        {"name":"payload","type":"cell"}
                    ],
                    "outputs": [
                        {"name":"transId","type":"uint64"}
                    ]
                }
            ],
            "data": [],
            "events": []
        }"#####;

        let contract_abi = ton_abi::Contract::load(contract).trust_me();
        let function = contract_abi.function("submitTransaction").trust_me();

        let _msg_code = base64::decode("te6ccgEBBAEA0QABRYgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/4MAQHhkN2GJNWURKaCKnkZsRQhhRpn6THu/L5UVbrQqftLTfUQT74cmHie7f1G6gzgchbLtyMtLAADdEgyd74v9hADgPx2uNPC/rcj5o9MEu0xQtT7O4QxICY7yPkDTSqLNRfNQAAAXh+Daz0/////xMdgs2ACAWOAAxkzX//CemECbh7vgh+JqjeKnKVxwwO21B0Xbqitsj/gAAAAAAAAAAAAAAADuaygBAMAAA==").unwrap();
        let tx = Transaction::construct_from_base64("te6ccgECDwEAArcAA7dxjJmv/+E9MIE3D3fBD8TVG8VOUrjhgdtqDou3VFbZH/AAALPVJCfkGksT3Y8aHAm7mnKfGA/AccQcwRmJeHov8yXElkW09QQwAACz0BBMOBYGHORAAFSAICXTqAUEAQIRDINHRh4pg8RAAwIAb8mPQkBMUWFAAAAAAAAEAAAAAAAEDt5ElKCY0ANTjCaw8ltpBJRSPdcEmknKxwOoduRmHbJAkCSUAJ1GT2MTiAAAAAAAAAAAWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAIJy3y4B4TEhaY3M9HQMWqBpVJc3IUvntA5EtNHkjN1t4sqjUitqEc3Fb6TafRVFXMJNDjglljNUbcLzalj6ghNYgAIB4AsGAgHdCQcBASAIAHXgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/4AAAWeqSE/IbAw5yISY7BZoAAAAAAAAAAQAEBIAoAsUgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/8ABjJmv/+E9MIE3D3fBD8TVG8VOUrjhgdtqDou3VFbZH/QdzWUAAYUWGAAABZ6pIT8hMDDnIhAAUWIADGTNf/8J6YQJuHu+CH4mqN4qcpXHDA7bUHRduqK2yP+DAwB4ZDdhiTVlESmgip5GbEUIYUaZ+kx7vy+VFW60Kn7S031EE++HJh4nu39RuoM4HIWy7cjLSwAA3RIMne+L/YQA4D8drjTwv63I+aPTBLtMULU+zuEMSAmO8j5A00qizUXzUAAAF4fg2s9P////8THYLNgDQFjgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/4AAAAAAAAAAAAAAAA7msoAQOAAA=").trust_me();
        let parser = FunctionAbi::new(function);
        parser.parse(&tx).unwrap();

        let outputs = parse_transaction_messages(&tx).unwrap();
        let raw_outputs = outputs
            .into_iter()
            .filter_map(|msg| {
                if msg.dst().is_none() {
                    msg.body()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        assert!(process_raw_outputs(&raw_outputs, function).is_ok());
    }

    #[test]
    fn test_execute() {
        let _contract_code = base64::decode("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").unwrap();
        let msg_code = base64::decode("te6ccgEBAQEAWwAAsUgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/8ABjJmv/+E9MIE3D3fBD8TVG8VOUrjhgdtqDou3VFbZH/QdzWUAAYUWGAAABZ6pIT8hMDDnIhA").unwrap();
        let account = Account::construct_from_base64("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").unwrap();
        let account = if let Account::Account(a) = account {
            a
        } else {
            unreachable!()
        };
        let mut executor = Executor::new(
            &SimpleClock,
            BlockchainConfig::default(),
            account,
            GenTimings::Known {
                gen_lt: 16916000,
                gen_utime: 12356000,
            },
        );
        executor
            .run(&Message::construct_from_bytes(&*msg_code).unwrap())
            .unwrap();
    }
    #[test]
    fn test_comment() {
        let comment = "i love memes and 🦀";

        let encoded_comment = create_comment_payload(comment).unwrap();
        assert_eq!(
            base64::encode(ton_types::serialize_toc(&encoded_comment.clone().into_cell()).unwrap()),
            "te6ccgEBAgEAHgABCAAAAAABACppIGxvdmUgbWVtZXMgYW5kIPCfpoA="
        );

        let decoded_comment = parse_comment_payload(encoded_comment).unwrap();
        assert_eq!(decoded_comment, comment);
    }

    #[test]
    fn test_encode_cell() {
        let expected = "te6ccgEBAQEAIgAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADA5";
        let tokens = &[Token::new("wa", TokenValue::Uint(Uint::new(12345, 256)))];
        let got = base64::encode(serialize_toc(&pack_into_cell(tokens).unwrap()).unwrap());
        assert_eq!(expected, got);
    }

    #[test]
    fn test_decode_cell() {
        let tokens = [Token::new("wa", TokenValue::Uint(Uint::new(12345, 256)))];
        let cell = pack_into_cell(&tokens).unwrap();
        let data = SliceData::construct_from_cell(cell).unwrap();
        let params = &[Param::new("wa", ParamType::Uint(256))];
        let got = unpack_from_cell(params, data, true).unwrap();
        assert_eq!(&tokens, got.as_slice());
    }

    #[test]
    fn test_decode_partial() {
        let tokens = [
            Token::new("first", TokenValue::Uint(Uint::new(12345, 256))),
            Token::new("second", TokenValue::Uint(Uint::new(1337, 64))),
        ];
        let cell = pack_into_cell(&tokens).unwrap();

        let data: SliceData = cell.into();

        let partial_params = &[Param::new("first", ParamType::Uint(256))];

        assert!(unpack_from_cell(partial_params, data.clone(), false).is_err());

        let got = unpack_from_cell(partial_params, data, true).unwrap();
        assert_eq!(
            &[Token::new("first", TokenValue::Uint(Uint::new(12345, 256))),],
            got.as_slice()
        );
    }

    #[test]
    fn unpack_header() {
        let body = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgEBAwEArAAB4by5SH0Glx7Jnb0imtClvhC4I0DPaT+/su49hM5DQH+xHrEtD9U2dQOJpD2J598bWtYTC4m1Ylxh6MSg9//WKgdEWH2fKWA3SuZNZZ7BBCeDpiGAfwIlOFF981WU06BclcAAAF7d/kbVGEk26dM7mRsgAQFlgBOzHFkFNmE1fX9Dpui0xVFiNtBGdDa6IIntwTxwGs9y4AAAAAAAAAAAAAAAB3NZQAA4AgAA").unwrap().as_slice()).unwrap().into();

        let ((pubkey, time, expire), remaining_body) =
            unpack_headers::<(PubkeyHeader, TimeHeader, ExpireHeader)>(&body).unwrap();

        assert_eq!(
            pubkey,
            Some(
                UInt256::from_str(
                    "1161f67ca580dd2b9935967b04109e0e988601fc0894e145f7cd56534e817257"
                )
                .unwrap()
            )
        );
        assert_eq!(time, 1629805419348);
        assert_eq!(expire, 1629805479);

        assert_eq!(read_function_id(&remaining_body).unwrap(), 1290691692); // sendTransaction input id
    }
}
