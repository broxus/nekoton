use anyhow::Result;
use nekoton_utils::TrustMe;
use ton_block::{
    AccountStuff, CommonMsgInfo, CurrencyCollection, Deserializable, Message, MsgAddressInt,
    OutAction, OutActions, Serializable,
};
use ton_types::SliceData;
use ton_vm::executor::gas::gas_state::Gas;
use ton_vm::stack::integer::IntegerData;
use ton_vm::stack::{savelist::SaveList, Stack};

pub type BehaviorModifiers = ton_vm::executor::BehaviorModifiers;
pub type StackItem = ton_vm::stack::StackItem;

#[derive(Debug, Copy, Clone)]
pub struct BriefBlockchainConfig {
    pub global_id: i32,
    pub capabilities: u64,
}

impl Default for BriefBlockchainConfig {
    fn default() -> Self {
        Self {
            global_id: 42,
            capabilities: 0x52e,
        }
    }
}

impl From<&ton_executor::BlockchainConfig> for BriefBlockchainConfig {
    fn from(value: &ton_executor::BlockchainConfig) -> Self {
        Self {
            global_id: value.global_id(),
            capabilities: value.capabilites(),
        }
    }
}

impl From<ton_executor::BlockchainConfig> for BriefBlockchainConfig {
    #[inline]
    fn from(value: ton_executor::BlockchainConfig) -> Self {
        Self::from(&value)
    }
}

pub fn call(
    utime: u32,
    lt: u64,
    account: &AccountStuff,
    stack: Stack,
    config: &BriefBlockchainConfig,
    modifiers: &BehaviorModifiers,
) -> Result<(ton_vm::executor::Engine, i32, bool), ExecutionError> {
    let state = match &account.storage.state {
        ton_block::AccountState::AccountActive { state_init, .. } => Ok(state_init),
        _ => Err(ExecutionError::AccountIsNotActive),
    }?;

    let mut ctrls = SaveList::new();
    ctrls
        .put(
            4,
            &mut StackItem::Cell(state.data.clone().unwrap_or_default()),
        )
        .map_err(|_| ExecutionError::FailedToPutDataIntoRegisters)?;

    let gas_limit = 1_000_000_000;
    let gas = Gas::new(gas_limit, 0, gas_limit, 10);

    let code = state.code.clone().ok_or(ExecutionError::AccountHasNoCode)?;

    let sci = build_contract_info(
        &account.addr,
        &account.storage.balance,
        utime,
        lt,
        lt,
        code.clone(),
        account.storage.init_code_hash.as_ref(),
    );
    ctrls
        .put(7, &mut sci.into_temp_data_item())
        .map_err(|_| ExecutionError::FailedToPutSciIntoRegisters)?;

    let mut engine = ton_vm::executor::Engine::with_capabilities(config.capabilities).setup(
        SliceData::load_cell(code).map_err(|_| ExecutionError::FailedToPutDataIntoRegisters)?,
        Some(ctrls),
        Some(stack),
        Some(gas),
    );
    engine.set_signature_id(config.global_id);
    engine.modify_behavior(modifiers.clone());

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
    account: &mut AccountStuff,
    msg: &Message,
    config: &BriefBlockchainConfig,
    modifiers: &ton_vm::executor::BehaviorModifiers,
) -> Result<ActionPhaseOutput, ExecutionError> {
    let msg_cell = msg
        .write_to_new_cell()
        .and_then(ton_types::BuilderData::into_cell)
        .map_err(|_| ExecutionError::FailedToSerializeMessage)?;

    let mut stack = Stack::new();
    let balance = account.storage.balance.grams.as_u128();
    let (function_selector, msg_balance) = match msg.header() {
        CommonMsgInfo::IntMsgInfo(_) => (
            ton_vm::int!(0),
            num_bigint::BigInt::from(1_000_000_000_000u64), // 1000 TON
        ),
        CommonMsgInfo::ExtInMsgInfo(_) => (ton_vm::int!(-1), num_bigint::BigInt::default()),
        CommonMsgInfo::ExtOutMsgInfo(_) => return Err(ExecutionError::InvalidMessageType),
    };
    stack
        .push(ton_vm::int!(balance)) // token balance of contract
        .push(ton_vm::int!(msg_balance)) // token balance of msg
        .push(StackItem::Cell(msg_cell)) // message
        .push(StackItem::Slice(msg.body().unwrap_or_default())) // message body
        .push(function_selector); // function selector

    let (engine, exit_code, success) = call(utime, lt, account, stack, config, modifiers)?;
    if !success {
        return Ok(ActionPhaseOutput {
            messages: None,
            exit_code,
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
    for action in actions.iter_mut() {
        if let OutAction::SendMsg { out_msg, .. } = std::mem::replace(action, OutAction::None) {
            msgs.push(out_msg);
        }
    }

    msgs.reverse();
    Ok(ActionPhaseOutput {
        messages: Some(msgs),
        exit_code,
    })
}

pub fn call_getter(
    utime: u32,
    lt: u64,
    account: &AccountStuff,
    method_id: u32,
    args: &[ton_vm::stack::StackItem],
    config: &BriefBlockchainConfig,
    modifiers: &ton_vm::executor::BehaviorModifiers,
) -> Result<VmGetterOutput, ExecutionError> {
    let mut stack = Stack::new();
    for arg in args {
        stack.push(arg.clone());
    }
    stack.push(ton_vm::int!(method_id));

    let (mut engine, exit_code, is_ok) = call(utime, lt, account, stack, config, modifiers)?;

    Ok(VmGetterOutput {
        stack: engine.withdraw_stack().storage,
        exit_code,
        is_ok,
    })
}

#[derive(Debug, Clone)]
pub struct VmGetterOutput {
    pub stack: Vec<ton_vm::stack::StackItem>,
    pub exit_code: i32,
    pub is_ok: bool,
}

fn build_contract_info(
    address: &MsgAddressInt,
    balance: &CurrencyCollection,
    block_unixtime: u32,
    block_lt: u64,
    tr_lt: u64,
    code: ton_types::Cell,
    init_code_hash: Option<&ton_types::UInt256>,
) -> ton_vm::SmartContractInfo {
    let mut info = ton_vm::SmartContractInfo::old_default(code);
    info.myself = SliceData::load_cell(address.serialize().unwrap_or_default()).trust_me();
    info.block_lt = block_lt;
    info.trans_lt = tr_lt;
    info.unix_time = block_unixtime;
    info.balance = balance.clone();
    if let Some(hash) = init_code_hash {
        info.set_init_code_hash(*hash);
    }
    info
}

pub struct ActionPhaseOutput {
    pub messages: Option<Vec<Message>>,
    pub exit_code: i32,
}

#[derive(thiserror::Error, Debug, Clone, Copy)]
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
