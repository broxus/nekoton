use std::sync::Arc;

use anyhow::Result;
use ton_block::{
    AccountStuff, CommonMsgInfo, CurrencyCollection, Deserializable, Message, MsgAddressInt,
    OutAction, OutActions, Serializable,
};
use ton_types::SliceData;
use ton_vm::executor::gas::gas_state::Gas;
use ton_vm::stack::integer::IntegerData;
use ton_vm::stack::{savelist::SaveList, Stack, StackItem};

pub fn call(
    utime: u32,
    lt: u64,
    mut account: AccountStuff,
    stack: Stack,
) -> Result<(ton_vm::executor::Engine, i32, bool), ExecutionError> {
    let state = match &mut account.storage.state {
        ton_block::AccountState::AccountActive(state) => Ok(state),
        _ => Err(ExecutionError::AccountIsNotActive),
    }?;

    let mut ctrls = SaveList::new();
    ctrls
        .put(
            4,
            &mut StackItem::Cell(state.data.clone().unwrap_or_default()),
        )
        .map_err(|_| ExecutionError::FailedToPutDataIntoRegisters)?;

    let sci = build_contract_info(&account.addr, &account.storage.balance, utime, lt, lt);
    ctrls
        .put(7, &mut sci.into_temp_data())
        .map_err(|_| ExecutionError::FailedToPutSciIntoRegisters)?;

    let gas_limit = 1_000_000_000;
    let gas = Gas::new(gas_limit, 0, gas_limit, 10);

    let code = state.code.clone().ok_or(ExecutionError::AccountHasNoCode)?;
    let mut engine = ton_vm::executor::Engine::new().setup(
        SliceData::from(code),
        Some(ctrls),
        Some(stack),
        Some(gas),
    );

    let result = engine.execute();

    Ok(match result {
        Err(err) => {
            let exception = ton_vm::error::tvm_exception(err)
                .map_err(|_| ExecutionError::FailedToParseException)?;
            let code = if let Some(code) = exception.custom_code() {
                code
            } else {
                !(exception
                    .exception_code()
                    .unwrap_or(ton_types::ExceptionCode::UnknownError) as i32)
            };

            (engine, code, false)
        }
        Ok(code) => (engine, code, true),
    })
}

pub fn call_msg(
    utime: u32,
    lt: u64,
    account: AccountStuff,
    msg: &Message,
) -> Result<ActionPhaseOutput, ExecutionError> {
    let msg_cell = msg
        .write_to_new_cell()
        .map_err(|_| ExecutionError::FailedToSerializeMessage)?;

    let mut stack = Stack::new();
    let balance = account.storage.balance.grams.value();
    let function_selector = match msg.header() {
        CommonMsgInfo::IntMsgInfo(_) => ton_vm::int!(0),
        CommonMsgInfo::ExtInMsgInfo(_) => ton_vm::int!(-1),
        CommonMsgInfo::ExtOutMsgInfo(_) => return Err(ExecutionError::InvalidMessageType),
    };
    stack
        .push(ton_vm::int!(balance)) // token balance of contract
        .push(ton_vm::int!(0)) // token balance of msg
        .push(StackItem::Cell(msg_cell.into())) // message
        .push(StackItem::Slice(msg.body().unwrap_or_default())) // message body
        .push(function_selector); // function selector

    let (engine, result_code, success) = call(utime, lt, account, stack)?;
    if !success {
        return Ok(ActionPhaseOutput {
            messages: None,
            result_code,
        });
    }

    // process out actions to get out messages
    let actions_cell = engine
        .get_actions()
        .as_cell()
        .map_err(|_| ExecutionError::FailedToRetrieveActions)?
        .clone();
    let mut actions = OutActions::construct_from_cell(actions_cell)
        .map_err(|_| ExecutionError::FailedToRetrieveActions)?;

    let mut msgs = Vec::new();
    for (_, action) in actions.iter_mut().enumerate() {
        if let OutAction::SendMsg { out_msg, .. } = std::mem::replace(action, OutAction::None) {
            msgs.push(out_msg);
        }
    }

    msgs.reverse();
    Ok(ActionPhaseOutput {
        messages: Some(msgs),
        result_code,
    })
}

fn build_contract_info(
    address: &MsgAddressInt,
    balance: &CurrencyCollection,
    block_unixtime: u32,
    block_lt: u64,
    tr_lt: u64,
) -> ton_vm::SmartContractInfo {
    let mut info =
        ton_vm::SmartContractInfo::with_myself(address.serialize().unwrap_or_default().into());
    *info.block_lt_mut() = block_lt;
    *info.trans_lt_mut() = tr_lt;
    *info.unix_time_mut() = block_unixtime;
    *info.balance_remaining_grams_mut() = balance.grams.0;
    *info.balance_remaining_other_mut() = balance.other_as_hashmap();

    info
}

pub struct ActionPhaseOutput {
    pub messages: Option<Vec<Message>>,
    pub result_code: i32,
}

#[derive(thiserror::Error, Debug)]
pub enum ExecutionError {
    #[error("Failed to serialize message")]
    FailedToSerializeMessage,
    #[error("Invalid message type")]
    InvalidMessageType,
    #[error("Account is not active")]
    AccountIsNotActive,
    #[error("Account has not code")]
    AccountHasNoCode,
    #[error("Failed to put data into registers")]
    FailedToPutDataIntoRegisters,
    #[error("Failed to put SCI into registers")]
    FailedToPutSciIntoRegisters,
    #[error("Failed to parse exception")]
    FailedToParseException,
    #[error("Failed to retrieve actions")]
    FailedToRetrieveActions,
}
