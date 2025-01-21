#![warn(
    missing_copy_implementations,
    macro_use_extern_crate,
    keyword_idents,
    explicit_outlives_requirements,
    meta_variable_misuse,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    clippy::await_holding_lock,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::doc_markdown,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::exit,
    clippy::explicit_into_iter_loop,
    clippy::filter_map_next,
    clippy::fn_params_excessive_bools,
    clippy::if_let_mutex,
    clippy::imprecise_flops,
    clippy::inefficient_to_string,
    clippy::let_unit_value,
    clippy::linkedlist,
    clippy::lossy_float_literal,
    clippy::macro_use_imports,
    clippy::map_flatten,
    clippy::map_unwrap_or,
    clippy::match_on_vec_items,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::mem_forget,
    clippy::mismatched_target_os,
    clippy::needless_borrow,
    clippy::needless_continue,
    clippy::option_option,
    clippy::ref_option_ref,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::string_add_assign,
    clippy::string_add,
    clippy::string_to_string,
    clippy::suboptimal_flops,
    clippy::todo,
    clippy::unimplemented,
    clippy::unnested_or_patterns,
    clippy::unused_self,
    clippy::verbose_file_reads,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    clippy::print_stdout,
    clippy::dbg_macro
)]
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
use ton_vm::executor::BehaviorModifiers;

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
pub use self::transaction_parser::TransactionParser;
pub use self::tvm::{BriefBlockchainConfig, StackItem, VmGetterOutput};

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
pub mod tvm;

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
    create_boc_payload(data.trim()).map_or_else(|_| create_comment_payload(data), Ok)
}

/// Creates slice data with string, encoded as comment
pub fn create_comment_payload(comment: &str) -> Result<SliceData> {
    TokenValue::pack_values_into_chain(
        &[
            0u32.token_value().unnamed(),
            comment.token_value().unnamed(),
        ],
        Vec::new(),
        &ton_abi::contract::ABI_VERSION_2_0,
    )
    .and_then(SliceData::load_builder)
}

pub fn parse_comment_payload(mut payload: SliceData) -> Option<String> {
    if payload.get_next_u32().ok()? != 0 {
        return None;
    }

    let mut cell = payload.checked_drain_reference().ok()?;

    let mut data = Vec::new();
    loop {
        data.extend_from_slice(cell.data());
        cell = match cell.reference(0) {
            Ok(cell) => cell.clone(),
            Err(_) => break,
        };
    }

    String::from_utf8(data).ok()
}

/// Creates slice data from base64 encoded boc
pub fn create_boc_payload(cell: &str) -> Result<SliceData> {
    let bytes = base64::decode(cell)?;
    let cell = ton_types::deserialize_tree_of_cells(&mut bytes.as_slice())
        .map_err(|_| UnpackerError::InvalidAbi)?;
    SliceData::load_cell(cell)
}

pub fn pack_into_cell(
    tokens: &[Token],
    abi_version: ton_abi::contract::AbiVersion,
) -> Result<ton_types::Cell> {
    let cells = Vec::new();
    TokenValue::pack_values_into_chain(tokens, cells, &abi_version).and_then(|x| x.into_cell())
}

pub fn unpack_from_cell(
    params: &[Param],
    mut cursor: SliceData,
    allow_partial: bool,
    abi_version: ton_abi::contract::AbiVersion,
) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();

    for param in params {
        let last = Some(param) == params.last();
        let (token_value, new_cursor) =
            TokenValue::read_from(&param.kind, cursor, last, &abi_version, allow_partial)?;

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
        Some(data) => SliceData::load_cell_ref(data).map_err(|_| ExtractionError::CellUnderflow)?,
        None => return Err(ExtractionError::AccountDataNotFound),
    };
    let data = data
        .get_next_bytes(32)
        .map_err(|_| ExtractionError::CellUnderflow)?;

    ed25519_dalek::PublicKey::from_bytes(&data).map_err(|_| ExtractionError::InvalidPublicKey)
}

pub fn get_state_init_hash(
    mut state_init: ton_block::StateInit,
    contract: &ton_abi::Contract,
    public_key: &Option<ed25519_dalek::PublicKey>,
    init_data: Vec<Token>,
) -> Result<UInt256> {
    state_init.data = if let Some(data) = state_init.data.take() {
        Some(
            insert_state_init_data(contract, SliceData::load_cell(data)?, public_key, init_data)?
                .into_cell(),
        )
    } else {
        None
    };
    state_init.hash()
}

pub fn insert_state_init_data(
    contract: &ton_abi::Contract,
    data: SliceData,
    public_key: &Option<ed25519_dalek::PublicKey>,
    tokens: Vec<Token>,
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
            0u64.serialize().and_then(SliceData::load_cell).trust_me(),
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

            let key = param.key.serialize();
            let key = key.and_then(SliceData::load_cell).trust_me();

            let builder = token.pack_into_chain(&contract.abi_version)?;
            map.set_builder(key, &builder)?;
        }
    }

    map.write_to_new_cell().and_then(SliceData::load_builder)
}

pub fn decode_input<'a>(
    contract: &'a ton_abi::Contract,
    message_body: SliceData,
    method: &MethodName,
    internal: bool,
) -> Result<Option<(&'a Function, Vec<Token>)>> {
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
) -> Result<Option<(&'a Function, Vec<Token>)>> {
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
) -> Result<Option<(&'a ton_abi::Event, Vec<Token>)>> {
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
        impl UnpackHeader for ($($header),+) {
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

#[derive(Copy, Clone, Debug)]
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

#[derive(Copy, Clone, Debug)]
pub struct TimeHeader;

impl UnpackHeader for TimeHeader {
    type Output = u64;

    fn unpack_header(body: &mut SliceData) -> Result<Self::Output> {
        body.get_next_u64()
    }
}

#[derive(Copy, Clone, Debug)]
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
    #[error("Invalid public key")]
    InvalidPublicKey,
}

pub fn code_to_tvc(code: ton_types::Cell) -> Result<ton_block::StateInit> {
    let pubkey_vec = smallvec![0; 32];
    let pubkey_len = pubkey_vec.len() * 8;
    let value = ton_types::BuilderData::with_raw(pubkey_vec, pubkey_len).unwrap_or_default();

    let mut init_data = ton_types::HashmapE::with_bit_len(ton_abi::Contract::DATA_MAP_KEYLEN);
    init_data.set_builder(
        0u64.serialize().and_then(SliceData::load_cell).unwrap(),
        &value,
    )?;

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

    pub fn run_getter<M>(
        &self,
        method_id: &M,
        args: &[StackItem],
    ) -> Result<VmGetterOutput, tvm::ExecutionError>
    where
        M: AsGetterMethodId + ?Sized,
    {
        self.run_getter_ext(
            method_id,
            args,
            &BriefBlockchainConfig::default(),
            &Default::default(),
        )
    }

    pub fn run_getter_ext<M>(
        &self,
        method_id: &M,
        args: &[StackItem],
        config: &BriefBlockchainConfig,
        modifier: &BehaviorModifiers,
    ) -> Result<VmGetterOutput, tvm::ExecutionError>
    where
        M: AsGetterMethodId + ?Sized,
    {
        let BlockStats {
            gen_utime, gen_lt, ..
        } = get_block_stats(self.clock, None, self.account_stuff.storage.last_trans_lt);

        tvm::call_getter(
            gen_utime,
            gen_lt,
            self.account_stuff,
            method_id.as_getter_method_id(),
            args,
            config,
            modifier,
        )
    }
}

pub trait AsGetterMethodId {
    fn as_getter_method_id(&self) -> u32;
}

impl<T: AsGetterMethodId + ?Sized> AsGetterMethodId for &T {
    fn as_getter_method_id(&self) -> u32 {
        T::as_getter_method_id(*self)
    }
}

impl<T: AsGetterMethodId + ?Sized> AsGetterMethodId for &mut T {
    fn as_getter_method_id(&self) -> u32 {
        T::as_getter_method_id(*self)
    }
}

impl AsGetterMethodId for u32 {
    fn as_getter_method_id(&self) -> u32 {
        *self
    }
}

impl AsGetterMethodId for str {
    fn as_getter_method_id(&self) -> u32 {
        let crc = crc_16(self.as_bytes());
        crc as u32 | 0x10000
    }
}

pub trait FunctionExt {
    fn parse(&self, tx: &ton_block::Transaction) -> Result<Vec<Token>>;

    fn run_local(
        &self,
        clock: &dyn Clock,
        account_stuff: AccountStuff,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        self.run_local_ext(
            clock,
            account_stuff,
            input,
            false,
            &BriefBlockchainConfig::default(),
        )
    }

    fn run_local_responsible(
        &self,
        clock: &dyn Clock,
        account_stuff: AccountStuff,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        self.run_local_ext(
            clock,
            account_stuff,
            input,
            true,
            &BriefBlockchainConfig::default(),
        )
    }

    fn run_local_ext(
        &self,
        clock: &dyn Clock,
        account_stuff: AccountStuff,
        input: &[Token],
        responsible: bool,
        config: &BriefBlockchainConfig,
    ) -> Result<ExecutionOutput>;
}

impl<T> FunctionExt for &T
where
    T: FunctionExt,
{
    fn parse(&self, tx: &ton_block::Transaction) -> Result<Vec<Token>> {
        T::parse(self, tx)
    }

    fn run_local_ext(
        &self,
        clock: &dyn Clock,
        account_stuff: AccountStuff,
        input: &[Token],
        responsible: bool,
        config: &BriefBlockchainConfig,
    ) -> Result<ExecutionOutput> {
        T::run_local_ext(self, clock, account_stuff, input, responsible, config)
    }
}

impl FunctionExt for Function {
    fn parse(&self, tx: &ton_block::Transaction) -> Result<Vec<Token>> {
        let abi = FunctionAbi::new(self);
        abi.parse(tx)
    }

    fn run_local_ext(
        &self,
        clock: &dyn Clock,
        mut account_stuff: AccountStuff,
        input: &[Token],
        responsible: bool,
        config: &BriefBlockchainConfig,
    ) -> Result<ExecutionOutput> {
        FunctionAbi::new(self).run_local(clock, &mut account_stuff, input, responsible, config)
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
        process_out_messages(&messages, self.abi)
    }

    fn run_local(
        &self,
        clock: &dyn Clock,
        account_stuff: &mut AccountStuff,
        input: &[Token],
        responsible: bool,
        config: &BriefBlockchainConfig,
    ) -> Result<ExecutionOutput> {
        let function = self.abi;

        let answer_id = if responsible {
            account_stuff.storage.balance.grams = ton_block::Grams::from(100_000_000_000_000u64); // 100 000 TON

            match input.first().map(|token| &token.value) {
                Some(TokenValue::Uint(ton_abi::Uint { number, size: 32 })) => number
                    .to_u32()
                    .map(Some)
                    .ok_or(AbiError::AnswerIdNotFound)?,
                _ => return Err(AbiError::AnswerIdNotFound.into()),
            }
        } else {
            None
        };

        let mut msg = if responsible {
            ton_block::Message::with_int_header(ton_block::InternalMessageHeader {
                src: ton_block::MsgAddressIntOrNone::Some(account_stuff.addr.clone()),
                dst: account_stuff.addr.clone(),
                ..Default::default()
            })
        } else {
            ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
                dst: account_stuff.addr.clone(),
                ..Default::default()
            })
        };

        let BlockStats {
            now_ms,
            gen_utime,
            gen_lt,
        } = get_block_stats(clock, None, account_stuff.storage.last_trans_lt);

        if responsible {
            msg.set_body(
                function
                    .encode_internal_input(input)
                    .and_then(SliceData::load_builder)?,
            );
        } else {
            msg.set_body(
                self.abi
                    .encode_run_local_input(now_ms, input)
                    .and_then(SliceData::load_builder)?,
            );
        }

        let tvm::ActionPhaseOutput {
            messages,
            exit_code: result_code,
        } = tvm::call_msg(
            gen_utime,
            gen_lt,
            account_stuff,
            &msg,
            config,
            &Default::default(),
        )?;

        let tokens = if let Some(answer_id) = answer_id {
            messages.map(|messages| {
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
                    None => Err(AbiError::NoMessagesProduced.into()),
                }
            })
        } else {
            messages.map(|messages| process_out_messages(&messages, self.abi))
        }
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

impl Executor {
    pub fn new(clock: &dyn Clock, config: BlockchainConfig, account: Account) -> Result<Self> {
        let last_trans_lt = match &account {
            Account::AccountNone => 0,
            Account::Account(a) => a.storage.last_trans_lt,
        };
        let BlockStats {
            gen_utime, gen_lt, ..
        } = get_block_stats(clock, None, last_trans_lt);

        Ok(Self::with_params(
            config,
            account,
            last_trans_lt,
            gen_utime,
            gen_lt,
        ))
    }

    pub fn with_params(
        config: BlockchainConfig,
        account: Account,
        last_trans_lt: u64,
        utime: u32,
        lt: u64,
    ) -> Self {
        Self {
            config,
            account,
            block_utime: utime,
            block_lt: lt,
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

    pub fn into_account(self) -> Account {
        self.account
    }

    pub fn last_transaction_lt(&self) -> u64 {
        self.last_transaction_lt.load(Ordering::Acquire)
    }

    /// Consumes account and executes message without mutating the account state.
    ///
    /// NOTE: produces transaction without state update
    pub fn run_once(mut self, message: &ton_block::Message) -> Result<ton_block::Transaction> {
        let mut executor = OrdinaryTransactionExecutor::new(self.config);
        executor.set_signature_check_disabled(self.disable_signature_check);

        let params = ton_executor::ExecuteParams {
            block_unixtime: self.block_utime,
            block_lt: self.block_lt,
            last_tr_lt: self.last_transaction_lt,
            behavior_modifiers: Some(executor.behavior_modifiers()),
            ..Default::default()
        };

        executor.execute_with_params(Some(message), &mut self.account, params)
    }

    /// Executes message without mutating the account state.
    ///
    /// NOTE: produces transaction without state update
    pub fn run(&self, message: &ton_block::Message) -> Result<ton_block::Transaction> {
        let mut executor = OrdinaryTransactionExecutor::new(self.config.clone());
        executor.set_signature_check_disabled(self.disable_signature_check);

        let params = ton_executor::ExecuteParams {
            block_unixtime: self.block_utime,
            block_lt: self.block_lt,
            last_tr_lt: self.last_transaction_lt.clone(),
            behavior_modifiers: Some(executor.behavior_modifiers()),
            ..Default::default()
        };

        executor.execute_with_params(Some(message), &mut self.account.clone(), params)
    }

    /// Executes message and mutates the account state.
    pub fn run_mut(&mut self, message: &ton_block::Message) -> Result<ton_block::Transaction> {
        let mut executor = OrdinaryTransactionExecutor::new(self.config.clone());
        executor.set_signature_check_disabled(self.disable_signature_check);

        let params = ton_executor::ExecuteParams {
            block_unixtime: self.block_utime,
            block_lt: self.block_lt,
            last_tr_lt: self.last_transaction_lt.clone(),
            behavior_modifiers: Some(executor.behavior_modifiers()),
            ..Default::default()
        };

        let transaction = executor.execute_with_params(Some(message), &mut self.account, params)?;

        if executor
            .config()
            .has_capability(ton_block::GlobalCapabilities::CapFastStorageStat)
        {
            self.account.update_storage_stat_fast()?;
        } else {
            self.account.update_storage_stat()?;
        }

        Ok(transaction)
    }
}

struct BlockStats {
    now_ms: u64,
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

    let now_ms = clock.now_ms_u64();

    match timings {
        Some(GenTimings::Known { gen_lt, gen_utime }) => BlockStats {
            now_ms,
            gen_utime,
            gen_lt,
        },
        _ => BlockStats {
            now_ms,
            gen_utime: (now_ms / 1000) as u32,
            gen_lt: last_trans_lt + UNKNOWN_TRANSACTION_LT_OFFSET,
        },
    }
}

/// `TokenValue::Optional` which always store its value in the cell
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
impl StandaloneToken for TokenValue {}
impl StandaloneToken for ton_block::Grams {}
impl StandaloneToken for ton_types::Cell {}
impl<T> StandaloneToken for Option<T> {}
impl<T> StandaloneToken for MaybeRef<T> {}
impl<T> StandaloneToken for Vec<T> {}
impl<T: StandaloneToken> StandaloneToken for Box<T> {}
impl<T: StandaloneToken> StandaloneToken for Arc<T> {}
impl<T: StandaloneToken> StandaloneToken for &T {}

pub fn default_blockchain_config() -> &'static ton_executor::BlockchainConfig {
    use once_cell::race::OnceBox;

    pub static CONFIG: OnceBox<ton_executor::BlockchainConfig> = OnceBox::new();
    CONFIG.get_or_init(Box::default)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ton_abi::{Param, ParamType, Uint};
    use ton_block::{Deserializable, Message, Transaction};

    use super::*;

    const DEFAULT_ABI_VERSION: ton_abi::contract::AbiVersion = ton_abi::contract::ABI_VERSION_2_0;

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
        let executor = Executor::new(&SimpleClock, BlockchainConfig::default(), account).unwrap();
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
    fn execute_getter() {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgEBAwEA1wACcIAStWnZig414CoO3Ix5SSSgxF+4p0D15b9rxM7Q6hTG2AQNApWGauQIQAABez2Soaga3FkkG3ymAgEAUAAACtJLqS2Krp5U49k0sATqkF/7CPTREi6T4gLBqodDaVGp3w9YHEEA3v8AIN0gggFMl7ohggEznLqxn3Gw7UTQ0x/THzHXC//jBOCk8mCDCNcYINMf0x/TH/gjE7vyY+1E0NMf0x/T/9FRMrryoVFEuvKiBPkBVBBV+RDyo/gAkyDXSpbTB9QC+wDo0QGkyMsfyx/L/8ntVA==").unwrap().as_slice()).unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell).unwrap();

        let res = ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        }
        .run_getter("seqno", &[])
        .unwrap();

        println!("{res:?}");
    }

    #[test]
    fn test_encode_cell() {
        let expected = "te6ccgEBAQEAIgAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADA5";
        let tokens = &[Token::new("wa", TokenValue::Uint(Uint::new(12345, 256)))];
        let got = base64::encode(
            ton_types::serialize_toc(&pack_into_cell(tokens, DEFAULT_ABI_VERSION).unwrap())
                .unwrap(),
        );
        assert_eq!(expected, got);
    }

    #[test]
    fn test_decode_cell() {
        let tokens = [Token::new("wa", TokenValue::Uint(Uint::new(12345, 256)))];
        let cell = pack_into_cell(&tokens, DEFAULT_ABI_VERSION).unwrap();
        let data = SliceData::construct_from_cell(cell).unwrap();
        let params = &[Param::new("wa", ParamType::Uint(256))];
        let got = unpack_from_cell(params, data, true, DEFAULT_ABI_VERSION).unwrap();
        assert_eq!(&tokens, got.as_slice());
    }

    #[test]
    fn test_decode_partial() {
        let tokens = [
            Token::new("first", TokenValue::Uint(Uint::new(12345, 256))),
            Token::new("second", TokenValue::Uint(Uint::new(1337, 64))),
        ];
        let data = pack_into_cell(&tokens, DEFAULT_ABI_VERSION)
            .and_then(SliceData::load_cell)
            .unwrap();

        let partial_params = &[Param::new("first", ParamType::Uint(256))];

        assert!(
            unpack_from_cell(partial_params, data.clone(), false, DEFAULT_ABI_VERSION).is_err()
        );

        let got = unpack_from_cell(partial_params, data, true, DEFAULT_ABI_VERSION).unwrap();
        assert_eq!(
            &[Token::new("first", TokenValue::Uint(Uint::new(12345, 256))),],
            got.as_slice()
        );
    }

    #[test]
    fn unpack_header() {
        let body = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgEBAwEArAAB4by5SH0Glx7Jnb0imtClvhC4I0DPaT+/su49hM5DQH+xHrEtD9U2dQOJpD2J598bWtYTC4m1Ylxh6MSg9//WKgdEWH2fKWA3SuZNZZ7BBCeDpiGAfwIlOFF981WU06BclcAAAF7d/kbVGEk26dM7mRsgAQFlgBOzHFkFNmE1fX9Dpui0xVFiNtBGdDa6IIntwTxwGs9y4AAAAAAAAAAAAAAAB3NZQAA4AgAA").unwrap().as_slice()).unwrap();
        let body = ton_types::SliceData::load_cell(body).unwrap();

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

    fn parse_cell(boc: &str) -> anyhow::Result<ton_types::Cell> {
        let boc = boc.trim();
        if boc.is_empty() {
            Ok(ton_types::Cell::default())
        } else {
            let body = base64::decode(boc)?;
            ton_types::deserialize_tree_of_cells(&mut body.as_slice())
        }
    }
    #[test]
    fn hello() -> Result<()> {
        let account = "te6ccgECCAEAAWMAAnHABjAbLHVZbm5Wmm0Trk7HDJTxd+zgvhn5aN3Oc9ROevxyEIJBQznnq6AAAMmJtAYVEUBKXTw4E0ACAQBQyLDWxgjLA6yhKJfmGLWfXdvRC34pWEXEek1ncgteNXUAAAGTRh7KRgEU/wD0pBP0vPLICwMCASAHBALm8nHXAQHAAPJ6gwjXGO1E0IMH1wHXCz/I+CjPFiPPFsn5AANx1wEBwwCagwfXAVETuvLgZN6AQNcBgCDXAYAg1wFUFnX5EPKo+CO78nlmvvgjgQcIoIED6KhSILyx8nQCIIIQTO5kbLrjDwHIy//LP8ntVAYFAD6CEBaePhG6jhH4AAKTINdKl3jXAdQC+wDo0ZMy8jziAJgwAtdM0PpAgwbXAXHXAXjXAddM+ABwgBAEqgIUscjLBVAFzxZQA/oCy2ki0CHPMSHXSaCECbmYM3ABywBYzxaXMHEBywASzOLJAfsAAATSMA==";
        let tx = "te6ccgECDAEAAnAAA7V2MBssdVlublaabROuTscMlPF37OC+Gflo3c5z1E56/HAAAyYm8XlAEKy5RXcT3fqNI58hfr0g4fdhYXBqSMX+HjpeTjGvKFBwAAMmJtAYVDZzz11gADRs0o5IBQQBAg8MQoYagXrEQAMCAG/Jg9CQTAosIAAAAAAAAgAAAAAAAiQUizx+r6MbUjovm5x2fP/W4DVTBrBq54SSuX2h3AswQFAWDACdQpDjE4gAAAAAAAAAAB3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIACCcrqCn0Efu7Vm1b+COCiqvWs4TNx2oxYmPkhulZEkArnZw95XLR5CFFs3X75wm4iqv+Nca0J1tAkWz6i3WmL0YEACAeAIBgEB3wcAsUgAxgNljqstzcrTTaJ1ydjhkp4u/ZwXwz8tG7nOeonPX48AGMBssdVlublaabROuTscMlPF37OC+Gflo3c5z1E56/HQ7msoAAYKLDAAAGTE3i8oBM5566xAAUWIAMYDZY6rLc3K002idcnY4ZKeLv2cF8M/LRu5znqJz1+ODAkB4Zrdv8UI48I32K2mO07+dwrfKPTgLSPJw+wxQdfU6xu1vMGDMUCrW17rxr2ihaAfQ9JTGcJz6WdXxAVsWl2YLYPyLDWxgjLA6yhKJfmGLWfXdvRC34pWEXEek1ncgteNXUAAAGTRiBG/mc89hBM7mRsgCgFlgAxgNljqstzcrTTaJ1ydjhkp4u/ZwXwz8tG7nOeonPX44AAAAAAAAAAAAAAAB3NZQAA4CwAA";

        let config = "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";

        let mut root_cell = parse_cell(account)?;
        let account = ton_block::Account::construct_from_cell(root_cell.clone())?;
        let tx = ton_block::Transaction::construct_from_base64(tx)?;
        let in_msg = tx.read_in_msg()?;

        let config = ton_block::ConfigParams::construct_from_base64(config)?;
        let executor = ton_executor::OrdinaryTransactionExecutor::new(
            ton_executor::BlockchainConfig::with_config(config, 42)?,
        );

        let last_trans_lt = match account.stuff() {
            Some(state) => state.storage.last_trans_lt,
            None => 0,
        };

        let params = ton_executor::ExecuteParams {
            block_unixtime: tx.now,
            block_lt: tx.lt,
            last_tr_lt: Arc::new(AtomicU64::new(last_trans_lt)),
            trace_callback: Some(Arc::new(move |args, info| {
                //actions.push(info);
                println!(
                    "MUUU {:?}",
                    args.ctrl(7).unwrap().as_tuple().unwrap().last().unwrap()
                );
                println!("\n ============ \n CMD: {}", info.cmd_str,);
                for item in &info.stack.storage {
                    println!("{item}");
                }
            })),
            ..Default::default()
        };

        let _ = executor.execute_with_libs_and_params(in_msg.as_ref(), &mut root_cell, params)?;

        Ok(())
    }
}
