use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use ton_abi::{Function, Param, Token, TokenValue};
use ton_block::{Account, AccountStuff, Deserializable, MsgAddrStd, MsgAddressInt, Serializable};
use ton_executor::{BlockchainConfig, OrdinaryTransactionExecutor, TransactionExecutor};
use ton_types::{SliceData, UInt256};

use super::models::{GenTimings, LastTransactionId};
use nekoton_utils::*;

pub use self::function_builder::*;
pub use self::message_builder::*;
pub use self::token_packer::*;
pub use self::token_unpacker::*;

mod function_builder;
mod message_builder;
mod token_packer;
mod token_unpacker;
mod tvm;

const TON_ABI_VERSION: u8 = 2;

pub fn create_comment_payload(comment: &str) -> Result<SliceData> {
    ton_abi::TokenValue::pack_values_into_chain(
        &[
            0u32.token_value().unnamed(),
            comment.token_value().unnamed(),
        ],
        Vec::new(),
        2,
    )
    .convert()
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

pub fn create_boc_payload(cell: &str) -> Result<SliceData> {
    let bytes = base64::decode(&cell)?;
    let cell = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(&bytes))
        .map_err(|_| UnpackerError::InvalidAbi)?;
    Ok(SliceData::from(cell))
}

pub fn pack_into_cell(tokens: &[ton_abi::Token]) -> Result<ton_types::Cell> {
    let cells = Vec::new();
    ton_abi::TokenValue::pack_values_into_chain(tokens, cells, TON_ABI_VERSION)
        .and_then(|x| x.into_cell())
        .convert()
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
            TokenValue::read_from(&param.kind, cursor, last, TON_ABI_VERSION).convert()?;

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
    account: &ton_block::AccountStuff,
) -> Result<ed25519_dalek::PublicKey, ExtractionError> {
    let state_init = match &account.storage.state {
        ton_block::AccountState::AccountActive(state_init) => state_init,
        _ => return Err(ExtractionError::AccountIsNotActive),
    };
    let mut data: ton_types::SliceData = match &state_init.data {
        Some(data) => data.into(),
        None => return Err(ExtractionError::AccountDataNotFound),
    };
    let data = data
        .get_next_bytes(32)
        .map_err(|_| ExtractionError::CellUnderflow)?;

    Ok(ed25519_dalek::PublicKey::from_bytes(&data).trust_me())
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
    let pubkey_vec = vec![0; 32];
    let pubkey_len = pubkey_vec.len() * 8;
    let value = ton_types::BuilderData::with_raw(pubkey_vec, pubkey_len).unwrap_or_default();

    let mut init_data = ton_types::HashmapE::with_bit_len(ton_abi::Contract::DATA_MAP_KEYLEN);
    init_data
        .set(0u64.write_to_new_cell().unwrap().into(), &value.into())
        .convert()?;

    let data = init_data
        .write_to_new_cell()
        .and_then(|data| data.into_cell())
        .convert()?;

    Ok(ton_block::StateInit {
        code: Some(code),
        data: Some(data),
        ..Default::default()
    })
}

pub trait FunctionExt {
    fn parse(&self, tx: &ton_block::Transaction) -> Result<Vec<Token>>;

    fn run_local(
        &self,
        account_stuff: ton_block::AccountStuff,
        timings: GenTimings,
        last_transaction_id: &LastTransactionId,
        input: &[Token],
    ) -> Result<ExecutionOutput>;
}

impl FunctionExt for &Function {
    fn parse(&self, tx: &ton_block::Transaction) -> Result<Vec<Token>> {
        let abi = FunctionAbi::new(self);
        abi.parse(tx)
    }

    fn run_local(
        &self,
        account_stuff: ton_block::AccountStuff,
        timings: GenTimings,
        last_transaction_id: &LastTransactionId,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        let abi = FunctionAbi::new(self);
        abi.run_local(account_stuff, timings, last_transaction_id, input)
    }
}

impl FunctionExt for Function {
    fn parse(&self, tx: &ton_block::Transaction) -> Result<Vec<Token>> {
        let abi = FunctionAbi::new(self);
        abi.parse(tx)
    }

    fn run_local(
        &self,
        account_stuff: ton_block::AccountStuff,
        timings: GenTimings,
        last_transaction_id: &LastTransactionId,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        let abi = FunctionAbi::new(self);
        abi.run_local(account_stuff, timings, last_transaction_id, input)
    }
}

struct FunctionAbi<'a> {
    fun: &'a Function,
}

impl<'a> FunctionAbi<'a> {
    fn new(fun: &'a Function) -> Self {
        Self { fun }
    }

    fn parse(&self, tx: &ton_block::Transaction) -> Result<Vec<Token>> {
        let messages = parse_transaction_messages(tx)?;
        process_out_messages(&*messages, self.fun)
    }

    fn run_local(
        &self,
        account_stuff: ton_block::AccountStuff,
        _timings: GenTimings,
        last_transaction_id: &LastTransactionId,
        input: &[Token],
    ) -> Result<ExecutionOutput> {
        let mut msg =
            ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
                dst: account_stuff.addr.clone(),
                ..Default::default()
            });

        msg.set_body(
            self.fun
                .encode_input(&HashMap::default(), input, false, None)
                .convert()?
                .into(),
        );

        let BlockStats {
            gen_utime, gen_lt, ..
        } = get_block_stats(None, last_transaction_id);

        let tvm::ActionPhaseOutput {
            messages,
            result_code,
        } = tvm::call_msg(gen_utime, gen_lt, account_stuff, &msg)?;

        let tokens = messages
            .map(|messages| process_out_messages(&messages, self.fun))
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

        if abi_function
            .is_my_output_message(body.clone(), false)
            .convert()?
        {
            let tokens = abi_function.decode_output(body, false).convert()?;

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
        let function_id = read_u32(body).map_err(|_| AbiError::InvalidOutputMessage)?;
        if abi_function.output_id != function_id {
            continue;
        }

        output = Some(abi_function.decode_output(body.clone(), false).convert()?);
        break;
    }

    match output {
        Some(a) => Ok(a),
        None if !abi_function.has_output() => Ok(Default::default()),
        None => Err(AbiError::NoMessagesProduced.into()),
    }
}

fn parse_transaction_messages(
    transaction: &ton_block::Transaction,
) -> Result<Vec<ton_block::Message>> {
    let mut messages = Vec::new();
    transaction
        .out_msgs
        .iterate_slices(|slice| {
            if let Ok(message) = slice
                .reference(0)
                .and_then(ton_block::Message::construct_from_cell)
            {
                messages.push(message);
            }
            Ok(true)
        })
        .convert()?;
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
    last_transaction_lt: u64,
}

fn get_block_stats(
    timings: Option<GenTimings>,
    last_transaction_id: &LastTransactionId,
) -> BlockStats {
    // Additional estimated logical time offset for the latest transaction id
    pub const UNKNOWN_TRANSACTION_LT_OFFSET: u64 = 10;

    let last_transaction_lt = match last_transaction_id {
        LastTransactionId::Exact(id) => id.lt,
        LastTransactionId::Inexact { latest_lt } => *latest_lt,
    };

    match timings {
        Some(GenTimings::Known { gen_lt, gen_utime }) => BlockStats {
            gen_utime,
            gen_lt,
            last_transaction_lt,
        },
        _ => BlockStats {
            gen_utime: Utc::now().timestamp() as u32,
            gen_lt: last_transaction_lt + UNKNOWN_TRANSACTION_LT_OFFSET,
            last_transaction_lt,
        },
    }
}

impl Executor {
    pub fn new(
        config: BlockchainConfig,
        account_stuff: AccountStuff,
        _timings: GenTimings,
        last_transaction_id: &LastTransactionId,
    ) -> Self {
        let BlockStats {
            gen_utime,
            gen_lt,
            last_transaction_lt,
        } = get_block_stats(None, last_transaction_id);

        Self {
            config,
            account: Account::Account(account_stuff),
            block_utime: gen_utime,
            block_lt: gen_lt,
            last_transaction_lt: Arc::new(AtomicU64::new(last_transaction_lt)),
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
        executor
            .execute_for_account(
                Some(message),
                &mut self.account,
                Default::default(),
                self.block_utime,
                self.block_lt,
                self.last_transaction_lt.clone(),
                false,
            )
            .convert()
    }
}

pub trait StandaloneToken {}
impl StandaloneToken for MsgAddressInt {}
impl StandaloneToken for MsgAddrStd {}
impl StandaloneToken for UInt256 {}
impl StandaloneToken for UInt128 {}
impl StandaloneToken for primitive_types::H160 {}
impl StandaloneToken for primitive_types::H256 {}
impl StandaloneToken for u16 {}
impl StandaloneToken for u32 {}
impl StandaloneToken for u64 {}
impl StandaloneToken for u128 {}
impl StandaloneToken for bool {}
impl StandaloneToken for Vec<u8> {}
impl StandaloneToken for TokenValue {}

#[cfg(test)]
mod tests {
    use ton_abi::{Param, ParamType, Uint};
    use ton_block::{Deserializable, Message, Transaction};
    use ton_types::serialize_toc;

    use super::*;

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

        let contract_abi = ton_abi::Contract::load(&mut std::io::Cursor::new(contract)).trust_me();
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
            BlockchainConfig::default(),
            account,
            GenTimings::Known {
                gen_lt: 16916000,
                gen_utime: 12356000,
            },
            &LastTransactionId::Inexact {
                latest_lt: 12356916000001,
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
            base64::encode(ton_types::serialize_toc(&encoded_comment.into_cell()).unwrap()),
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
}
