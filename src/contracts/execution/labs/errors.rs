use std::fmt::Formatter;

use thiserror::Error;
use ton_block::{AccStatusChange, ComputeSkipReason, MsgAddressInt};

#[derive(Error, Debug)]
pub enum TvmExecError {
    TvmExecutionFailed {
        err_message: String,
        code: i32,
        exit_arg: i32,
        address: MsgAddressInt,
        gas_used: Option<u64>,
    },
    LowBalance {
        address: MsgAddressInt,
        balance: u64,
    },
    TvmExecutionSkipped {
        reason: ComputeSkipReason,
        address: MsgAddressInt,
        balance: u64,
    },
    UnknownExecutionError(String),
    StoragePhaseFailed {
        acc_status_change: AccStatusChange,
        address: MsgAddressInt,
        balance: u64,
    },
    ActionPhaseFailed {
        result_code: i32,
        valid: bool,
        no_funds: bool,
        address: MsgAddressInt,
        balance: u64,
    },
    TransactionAborted,
}

impl std::fmt::Display for TvmExecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self)
    }
}
