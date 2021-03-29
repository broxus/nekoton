mod abi;
mod compiled;

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use anyhow::Result;
use ton_block::Transaction;
use ton_executor::{BlockchainConfig, OrdinaryTransactionExecutor, TransactionExecutor};
use ton_types::Cell;

use crate::utils::NoFailure;
