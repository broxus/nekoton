/*
 * Copyright 2018-2020 ..
 *
 * Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
 * this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific TON DEV software governing permissions and
 * limitations under the License.
 *
 */

use std::convert::TryFrom;
use std::sync::{atomic::AtomicU64, Arc};

use num_traits::ToPrimitive;
use serde::de::Unexpected::TupleVariant;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ton_block::{AccStatusChange, Account, Message, Serializable};
use ton_executor::{
    BlockchainConfig, ExecutorError, OrdinaryTransactionExecutor, TransactionExecutor,
};
use ton_sdk::{AbiContract, TransactionFees};
use ton_types::{Cell, SliceData};
use ton_vm::error::TvmError;
use ton_vm::stack::StackItem;

use models::MessageBodyType;

// use super::stack::serialize_item;
// use super::types::{ExecutionOptions, ResolvedExecutionOptions};
// use crate::boc::internal::{
//     deserialize_cell_from_boc, deserialize_object_from_boc, deserialize_object_from_cell,
//     serialize_cell_to_boc, serialize_object_to_base64, serialize_object_to_boc,
//     serialize_object_to_cell,
// };
// use crate::client::ClientContext;
// use crate::contracts::execution::labs::utils::{
//     deserialize_cell_from_boc, deserialize_object_from_boc, deserialize_object_from_cell,
//     serialize_object_to_cell,
// };
// use crate::error::ClientResult;
// use crate::processing::{parsing::decode_output, DecodedOutput};
// use crate::utils::NoFailure;
// use crate::{abi::Abi, boc::BocCacheType};
use crate::contracts::execution::labs::errors::TvmExecError;
use crate::contracts::execution::labs::models::{
    Abi, ExecutionOptions, ParamsOfDecodeMessage, ResolvedExecutionOptions,
};
use crate::contracts::execution::labs::utils::{
    deserialize_cell_from_boc, deserialize_object_from_boc, deserialize_object_from_cell,
    serialize_cell_to_base64, serialize_object_to_base64, serialize_object_to_cell,
};
use crate::utils::NoFailure;
use ton_abi::token::Detokenizer;
use ton_abi::{Param, Token, TokenValue};

mod errors;
mod models;
mod utils;

type ClientResult<T> = anyhow::Result<T>;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum AccountForExecutor {
    /// Non-existing account to run a creation internal message.
    /// Should be used with `skip_transaction_check = true` if the message has no deploy data
    /// since transactions on the uninitialized account are always aborted
    None,
    /// Emulate uninitialized account to run deploy message
    Uninit,
    /// Account state to run message
    Account {
        /// Account BOC. Encoded as base64.
        boc: String,
        /// Flag for running account with the unlimited balance. Can be used to calculate
        /// transaction fees without balance check
        unlimited_balance: Option<bool>,
    },
}

impl Default for AccountForExecutor {
    fn default() -> Self {
        AccountForExecutor::None
    }
}

const UNLIMITED_BALANCE: u64 = u64::MAX;

impl AccountForExecutor {
    pub async fn get_account(
        &self,
        address: ton_block::MsgAddressInt,
    ) -> ClientResult<(Cell, Option<ton_block::CurrencyCollection>)> {
        match self {
            AccountForExecutor::None => {
                let account = Account::AccountNone.write_to_new_cell().unwrap().into();
                Ok((account, None))
            }
            AccountForExecutor::Uninit => {
                let last_paid =
                    (chrono::prelude::Utc::now().timestamp_millis() as u64 / 1000) as u32;
                let account = Account::uninit(address, 0, last_paid, UNLIMITED_BALANCE.into());
                let account = serialize_object_to_cell(&account)?;
                Ok((account, None))
            }
            AccountForExecutor::Account {
                boc,
                unlimited_balance,
            } => {
                if unlimited_balance.unwrap_or_default() {
                    let mut account: Account = deserialize_object_from_boc(&boc).await?.object;
                    let original_balance =
                        account
                            .balance()
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "can not set unlimited balance for non existed account",
                                )
                            })?
                            .clone();
                    let mut balance = original_balance.clone();
                    balance.grams = UNLIMITED_BALANCE.into();
                    account.set_balance(balance);
                    let account = serialize_object_to_cell(&account)?;
                    Ok((account, Some(original_balance)))
                } else {
                    let (_, account) = deserialize_cell_from_boc(&boc).await?;
                    Ok((account, None))
                }
            }
        }
    }

    pub fn restore_balance_if_needed(
        account: Cell,
        balance: Option<ton_block::CurrencyCollection>,
    ) -> ClientResult<Cell> {
        if let Some(balance) = balance {
            let mut account: Account = deserialize_object_from_cell(account)?;
            account.set_balance(balance);
            serialize_object_to_cell(&account)
        } else {
            Ok(account)
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ParamsOfRunExecutor {
    /// Input message BOC. Must be encoded as base64.
    pub message: String,
    /// Account to run on executor
    pub account: AccountForExecutor,
    /// Execution options.
    pub execution_options: Option<ExecutionOptions>,
    /// Contract ABI for decoding output messages
    pub abi: Option<Abi>,
    /// Skip transaction check flag
    pub skip_transaction_check: Option<bool>,
    /// Return updated account flag. Empty string is returned if the flag is `false`
    pub return_updated_account: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ParamsOfRunTvm {
    /// Input message BOC. Must be encoded as base64.
    pub message: String,
    /// Account BOC. Must be encoded as base64.
    pub account: String,
    /// Execution options.
    pub execution_options: Option<ExecutionOptions>,
    /// Contract ABI for decoding output messages
    pub abi: Option<Abi>,
    /// Cache type to put the result. The BOC itself returned if no cache type provided
    pub boc_cache: Option<()>,
    /// Return updated account flag. Empty string is returned if the flag is `false`
    pub return_updated_account: Option<bool>,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct ResultOfRunExecutor {
    /// Parsed transaction.
    ///
    /// In addition to the regular transaction fields there is a
    /// `boc` field encoded with `base64` which contains source
    /// transaction BOC.
    pub transaction: Value,

    /// List of output messages' BOCs. Encoded as `base64`
    pub out_messages: Vec<String>,

    /// Optional decoded message bodies according to the optional
    /// `abi` parameter.
    pub decoded: Option<DecodedOutput>,

    /// Updated account state BOC. Encoded as `base64`
    pub account: String,

    /// Transaction fees
    pub fees: TransactionFees,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct DecodedOutput {
    /// Decoded bodies of the out messages.
    ///
    /// If the message can't be decoded, then `None` will be stored in
    /// the appropriate position.
    pub out_messages: Vec<Option<DecodedMessageBody>>,

    /// Decoded body of the function output message.
    pub output: Option<Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct DecodedMessageBody {
    /// Type of the message body content.
    pub body_type: MessageBodyType,

    /// Function or event name.
    pub name: String,

    /// Parameters or result value.
    pub value: Option<Value>,

    /// Function header.
    pub header: Option<FunctionHeader>,
}

pub struct DecodedMessage {
    pub function_name: String,
    pub tokens: Vec<Token>,
    pub params: Vec<Param>,
}

impl DecodedMessageBody {
    fn new(
        body_type: MessageBodyType,
        decoded: DecodedMessage,
        header: Option<FunctionHeader>,
    ) -> ClientResult<Self> {
        let value = Detokenizer::detokenize_to_json_value(&decoded.params, &decoded.tokens)
            .map_err(|e| anyhow::Error::msg(e.to_string()))?;
        Ok(Self {
            body_type,
            name: decoded.function_name,
            value: Some(value),
            header,
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Default)]
pub struct FunctionHeader {
    /// Message expiration time in seconds.
    /// If not specified - calculated automatically from message_expiration_timeout(),
    /// try_index and message_expiration_timeout_grow_factor() (if ABI includes `expire` header).
    pub expire: Option<u32>,

    /// Message creation time in milliseconds. If not specified, `now` is used
    /// (if ABI includes `time` header).
    pub time: Option<u64>,

    /// Public key is used by the contract to check the signature. Encoded in `hex`.
    /// If not specified, method fails with exception (if ABI includes `pubkey` header)..
    pub pubkey: Option<String>,
}

impl FunctionHeader {
    pub fn from(tokens: &Vec<Token>) -> ClientResult<Option<Self>> {
        fn required_time(token: &Token) -> ClientResult<u64> {
            match &token.value {
                TokenValue::Time(v) => Ok(v.clone()),
                _ => Err(anyhow::anyhow!("`time` header has invalid format",)),
            }
        }
        fn required_expire(token: &Token) -> ClientResult<u32> {
            match &token.value {
                TokenValue::Expire(v) => Ok(v.clone()),
                _ => Err(anyhow::anyhow!("`expire` header has invalid format",)),
            }
        }
        fn required_pubkey(token: &Token) -> ClientResult<Option<String>> {
            match token.value {
                TokenValue::PublicKey(key) => Ok(key.as_ref().map(|x| hex::encode(x.as_bytes()))),
                _ => Err(anyhow::anyhow!("`pubkey` header has invalid format",)),
            }
        }

        if tokens.len() == 0 {
            return Ok(None);
        }
        let mut header = FunctionHeader::default();
        for token in tokens {
            match token.name.as_str() {
                "time" => header.time = Some(required_time(&token)?),
                "expire" => header.expire = Some(required_expire(&token)?),
                "pubkey" => header.pubkey = required_pubkey(&token)?,
                _ => (),
            }
        }
        Ok(Some(header))
    }
}

// #[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
// pub struct ResultOfRunTvm {
//     /// List of output messages' BOCs. Encoded as `base64`
//     pub out_messages: Vec<String>,
//
//     /// Optional decoded message bodies according to the optional
//     /// `abi` parameter.
//     pub decoded: Option<DecodedOutput>,
//
//     /// Updated account state BOC. Encoded as `base64`.
//     /// Attention! Only `account_state.storage.state.data` part of the BOC is updated.
//     pub account: String,
// }
//
// async fn parse_transaction(
//     context: &Arc<ClientContext>,
//     transaction: &ton_block::Transaction,
// ) -> ClientResult<Value> {
//     Ok(crate::boc::parse_transaction(
//         context.clone(),
//         crate::boc::ParamsOfParse {
//             boc: serialize_object_to_base64(transaction, "transaction")?,
//         },
//     )
//     .await?
//     .parsed)
// }

/// Emulates all the phases of contract execution locally
///
/// Performs all the phases of contract execution on Transaction Executor -
/// the same component that is used on Validator Nodes.
///
/// Can be used for contract debugginh, to find out the reason why message was not delivered successfully
///  - because Validators just throw away the failed external inbound messages, here you can catch them.
///
/// Another use case is to estimate fees for message execution. Set  `AccountForExecutor::Account.unlimited_balance`
/// to `true` so that emulation will not depend on the actual balance.
///
/// One more use case - you can produce the sequence of operations,
/// thus emulating the multiple contract calls locally.
/// And so on.
///
/// To get the account BOC (bag of cells) - use `net.query` method to download it from GraphQL API
/// (field `boc` of `account`) or generate it with `abi.encode_account` method.
/// To get the message BOC - use `abi.encode_message` or prepare it any other way, for instance, with FIFT script.
///
/// If you need this emulation to be as precise as possible then specify `ParamsOfRunExecutor` parameter.
/// If you need to see the aborted transaction as a result, not as an error, set `skip_transaction_check` to `true`.

async fn extract_error<F>(
    transaction: &ton_sdk::Transaction,
    contract_info: impl FnOnce() -> F,
) -> Result<(), TvmExecError>
where
    F: futures::Future<Output = ClientResult<(ton_block::MsgAddressInt, u64)>>,
{
    if let Some(storage) = &transaction.storage {
        if storage.status_change != AccStatusChange::Unchanged {
            let (address, balance) = contract_info()
                .await
                .map_err(|e| TvmExecError::UnknownExecutionError(e.to_string()))?;
            return Err(TvmExecError::StoragePhaseFailed {
                acc_status_change: storage.status_change.clone(),
                address,
                balance,
            });
        }
    }

    if let Some(reason) = transaction.compute.skipped_reason.clone() {
        let (address, balance) = contract_info()
            .await
            .map_err(|e| TvmExecError::UnknownExecutionError(e.to_string()))?;
        return Err(TvmExecError::TvmExecutionSkipped {
            reason,
            address,
            balance,
        });
    }

    if transaction.compute.success.is_none() || !transaction.compute.success.unwrap() {
        let (address, _) = contract_info()
            .await
            .map_err(|e| TvmExecError::UnknownExecutionError(e.to_string()))?;
        return Err(TvmExecError::TvmExecutionFailed {
            err_message: "compute phase isn't succeeded".to_string(),
            code: transaction.compute.exit_code.unwrap_or(-1),
            exit_arg: transaction.compute.exit_arg.map(i32::into).unwrap_or(0), //todo not sure
            address,
            gas_used: Some(transaction.compute.gas_used),
        });
    }

    if let Some(action) = &transaction.action {
        if !action.success {
            let (address, balance) = contract_info()
                .await
                .map_err(|e| TvmExecError::UnknownExecutionError(e.to_string()))?;
            return Err(TvmExecError::ActionPhaseFailed {
                result_code: action.result_code,
                valid: action.valid,
                no_funds: action.no_funds,
                address,
                balance,
            });
        }
    }

    Ok(())
}

pub(crate) async fn calc_transaction_fees<F>(
    transaction: &ton_block::Transaction,
    skip_check: bool,
    contract_info: impl FnOnce() -> F,
) -> Result<ton_sdk::TransactionFees, TvmExecError>
where
    F: futures::Future<Output = ClientResult<(ton_block::MsgAddressInt, u64)>>,
{
    let transaction = ton_sdk::Transaction::try_from(transaction)
        .map_err(|e| TvmExecError::UnknownExecutionError(e.to_string()))?;

    if !transaction.is_aborted() || skip_check {
        return Ok(transaction.calc_fees());
    }

    let mut error = match extract_error(&transaction, contract_info).await {
        Err(err) => err,
        Ok(_) => TvmExecError::TransactionAborted,
    };

    Err(error)
}

pub async fn run_executor(
    message: Message,
    params: ParamsOfRunExecutor,
) -> ClientResult<ResultOfRunExecutor> {
    let msg_address = message
        .dst()
        .ok_or_else(|| TvmExecError::UnknownExecutionError("Invalid message type".into()))?;
    let (account, _) = params.account.get_account(msg_address.clone()).await?;

    let options = ResolvedExecutionOptions::from_options(params.execution_options).await?;

    let account_copy = account.clone();
    let contract_info = move || async move {
        let account: ton_block::Account = deserialize_object_from_cell(account_copy.clone())?;
        match account.stuff() {
            Some(stuff) => {
                let balance = stuff
                    .storage
                    .balance
                    .grams
                    .value()
                    .to_u64()
                    .unwrap_or_default();
                Ok((stuff.addr.clone(), balance))
            }
            None => Ok((msg_address.clone(), 0)),
        }
    };

    let (transaction, modified_account) =
        call_executor(account.clone(), message, options, contract_info.clone()).await?;

    let fees = calc_transaction_fees(
        &transaction,
        params.skip_transaction_check.unwrap_or_default(),
        contract_info,
    )
    .await?;

    let mut out_messages = vec![];
    for i in 0..transaction.outmsg_cnt {
        let message = transaction
            .get_out_msg(i)
            .convert()?
            .ok_or_else(|| anyhow::anyhow!("message missing"))?;
        out_messages.push(serialize_object_to_base64(&message)?);
    }

    // TODO decode Message object without converting to string
    let decoded = if let Some(abi) = params.abi.as_ref() {
        Some(decode_output(abi, out_messages.clone()).await?)
    } else {
        None
    };

    let account = if params.return_updated_account.unwrap_or_default() {
        serialize_cell_to_base64(&modified_account)?
    } else {
        String::new()
    };

    Ok(ResultOfRunExecutor {
        out_messages,
        transaction: parse_transaction(&transaction).await?,
        account,
        decoded,
        fees,
    })
}

pub(crate) async fn decode_output(abi: &Abi, messages: Vec<String>) -> ClientResult<DecodedOutput> {
    let mut out_messages = Vec::new();
    let mut output = None;
    for message in messages {
        let decode_result = decode_message(ParamsOfDecodeMessage {
            message,
            abi: abi.clone(),
        })
        .await;
        let decoded = match decode_result {
            Ok(decoded) => {
                if decoded.body_type == MessageBodyType::Output {
                    output = decoded.value.clone();
                }
                Some(decoded)
            }
            Err(_) => None,
        };
        out_messages.push(decoded);
    }
    Ok(DecodedOutput {
        out_messages,
        output,
    })
}

pub async fn decode_message(params: ParamsOfDecodeMessage) -> ClientResult<DecodedMessageBody> {
    let (abi, message) = prepare_decode(&params).await?;
    if let Some(body) = message.body() {
        decode_body(abi, body, message.is_internal())
    } else {
        Err(anyhow::anyhow!("The message body is empty",))
    }
}

fn decode_body(
    abi: AbiContract,
    body: SliceData,
    is_internal: bool,
) -> ClientResult<DecodedMessageBody> {
    if let Ok(output) = abi.decode_output(body.clone(), is_internal) {
        if abi.events().get(&output.function_name).is_some() {
            DecodedMessageBody::new(MessageBodyType::Event, output, None)
        } else {
            DecodedMessageBody::new(MessageBodyType::Output, output, None)
        }
    } else if let Ok(input) = abi.decode_input(body.clone(), is_internal) {
        // TODO: add pub access to `abi_version` field of `Contract` struct.
        let abi_version = abi
            .functions()
            .values()
            .next()
            .map(|x| x.abi_version)
            .unwrap_or(1);
        let (header, _, _) =
            ton_abi::Function::decode_header(abi_version, body.clone(), abi.header(), is_internal)
                .map_err(|err| anyhow::anyhow!(format!("Can't decode function header: {}", err)))?;
        DecodedMessageBody::new(
            MessageBodyType::Input,
            input,
            FunctionHeader::from(&header)?,
        )
    } else {
        Err(anyhow::anyhow!(
            "The message body does not match the specified ABI",
        ))
    }
}

async fn prepare_decode(
    params: &ParamsOfDecodeMessage,
) -> ClientResult<(AbiContract, ton_block::Message)> {
    let abi = params.abi.json_string()?;
    let abi = AbiContract::load(abi.as_bytes()).convert()?;
    let message = deserialize_object_from_boc(&params.message).await?;
    Ok((abi, message.object))
}

//
// pub fn serialize_items<'a>(
//     items: Box<dyn Iterator<Item = &'a StackItem> + 'a>,
//     flatten_lists: bool,
// ) -> ClientResult<Value> {
//     let mut stack = vec![(vec![], items)];
//     let mut list_items: Option<Vec<Value>> = None;
//     loop {
//         let (mut vec, mut iter) = stack.pop().unwrap();
//         let next = iter.next();
//         if let Some(list) = list_items.take() {
//             // list is ended if current tuple has next element
//             // or it already contains more than one element
//             // or element type in current tuple is not equal to list items type
//             if next.is_some() || vec.len() != 1 || !is_equal_type(&vec[0], &list[0]) {
//                 vec.push(json!(ComplexType::List(list)));
//             } else {
//                 list_items = Some(list);
//             }
//         }
//
//         if let Some(item) = next {
//             match process_item(item)? {
//                 ProcessingResult::Serialized(value) => {
//                     vec.push(value);
//                     stack.push((vec, iter));
//                 }
//                 ProcessingResult::Nested(nested_iter) => {
//                     stack.push((vec, iter));
//                     stack.push((vec![], nested_iter));
//                 }
//             }
//         } else {
//             if let Some((parent_vec, _)) = stack.last_mut() {
//                 // list starts from tuple with 2 elements: some value and null,
//                 // the value becomes the last list item
//                 if vec.len() == 2 && vec[1] == Value::Null && flatten_lists {
//                     vec.resize(1, Value::Null);
//                     list_items = Some(vec);
//                 } else if let Some(list) = list_items.take() {
//                     vec.extend(list.into_iter());
//                     list_items = Some(vec);
//                 } else {
//                     parent_vec.push(Value::Array(vec));
//                 }
//             } else {
//                 return Ok(Value::Array(vec));
//             }
//         }
//     }
// }

/// Executes get-methods of ABI-compatible contracts
///
/// Performs only a part of compute phase of transaction execution
/// that is used to run get-methods of ABI-compatible contracts.
///  
/// If you try to run get-methods with `run_executor` you will get an error, because it checks ACCEPT and exits
/// if there is none, which is actually true for get-methods.
///
///  To get the account BOC (bag of cells) - use `net.query` method to download it from GraphQL API
/// (field `boc` of `account`) or generate it with `abi.encode_account method`.
/// To get the message BOC - use `abi.encode_message` or prepare it any other way, for instance, with FIFT script.
///
/// Attention! Updated account state is produces as well, but only
/// `account_state.storage.state.data`  part of the BOC is updated.
// pub async fn run_tvm(params: ParamsOfRunTvm) -> ClientResult<ResultOfRunTvm> {
//     let account = deserialize_object_from_boc(&params.account, "account").await?;
//     let message = deserialize_object_from_boc::<Message>(&params.message, "message")
//         .await?
//         .object;
//     let options =
//         ResolvedExecutionOptions::from_options(&context, params.execution_options).await?;
//     let stuff = match account.object {
//         ton_block::Account::AccountNone => Err(Error::invalid_account_boc("Acount is None")),
//         ton_block::Account::Account(stuff) => Ok(stuff),
//     }?;
//
//     let (messages, stuff) = super::call_tvm::call_tvm_msg(stuff, options, &message)?;
//
//     let mut out_messages = vec![];
//     for message in messages {
//         out_messages.push(
//             serialize_object_to_boc(&context, &message, "message", params.boc_cache.clone())
//                 .await?,
//         );
//     }
//
//     // TODO decode Message object without converting to string
//     let decoded = if let Some(abi) = params.abi.as_ref() {
//         Some(decode_output(&context, abi, out_messages.clone()).await?)
//     } else {
//         None
//     };
//
//     let account = if params.return_updated_account.unwrap_or_default() {
//         serialize_object_to_boc(
//             &ton_block::Account::Account(stuff),
//             "account",
//             params.boc_cache,
//         )
//         .await?
//     } else {
//         String::new()
//     };
//
//     Ok(ResultOfRunTvm {
//         out_messages,
//         account,
//         decoded,
//     })
// }

async fn call_executor<F>(
    mut account: Cell,
    msg: ton_block::Message,
    options: ResolvedExecutionOptions,
    contract_info: impl FnOnce() -> F,
) -> Result<(ton_block::Transaction, Cell), TvmExecError>
where
    F: futures::Future<Output = ClientResult<(ton_block::MsgAddressInt, u64)>>,
{
    let executor = OrdinaryTransactionExecutor::new(
        Arc::try_unwrap(options.blockchain_config).unwrap_or_else(|arc| arc.as_ref().clone()),
    );
    let result = executor.execute(
        Some(&msg),
        &mut account,
        options.block_time,
        options.block_lt,
        Arc::new(AtomicU64::new(options.transaction_lt)),
        false,
    );

    let transaction = match result {
        Ok(transaction) => transaction,
        Err(err) => {
            let err_message = err.to_string();
            let err = match contract_info().await {
                Ok((address, balance)) => match &err.downcast_ref::<ExecutorError>() {
                    Some(ExecutorError::NoAcceptError(code, exit_arg)) => {
                        let exit_arg = exit_arg
                            .as_ref()
                            .map(|item| serialize_item(item))
                            .transpose()?;
                        TvmExecError::TvmExecutionFailed {
                            err_message,
                            code: *code,
                            exit_arg,
                            address,
                            gas_used: None,
                        }
                    }
                    Some(ExecutorError::NoFundsToImportMsg) => {
                        TvmExecError::LowBalance { address, balance }
                    }
                    Some(ExecutorError::ExtMsgComputeSkipped(reason)) => {
                        TvmExecError::TvmExecutionSkipped {
                            reason: reason.clone(),
                            address,
                            balance,
                        }
                    }
                    _ => TvmExecError::UnknownExecutionError(err_message),
                },
                Err(err) => err,
            };
            return Err(err);
        }
    };

    Ok((transaction, account))
}

impl ResolvedExecutionOptions {
    pub async fn from_options(options: Option<ExecutionOptions>) -> ClientResult<Self> {
        let options = options.unwrap_or_default();

        let config = BlockchainConfig::default();

        let block_lt = options
            .block_lt
            .unwrap_or(options.transaction_lt.unwrap_or(1_000_001) - 1);
        let transaction_lt = options.transaction_lt.unwrap_or(block_lt + 1);
        let block_time = options
            .block_time
            .unwrap_or_else(|| (chrono::Utc::now().timestamp_millis() / 1000) as u32);

        Ok(Self {
            block_lt,
            block_time,
            blockchain_config: Arc::new(config),
            transaction_lt,
        })
    }
}
