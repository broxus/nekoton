use nekoton_abi::num_bigint::BigUint;
use nekoton_abi::VmGetterOutput;
use thiserror::Error;
use ton_block::{Deserializable, MsgAddressInt};
use ton_types::Cell;

#[derive(Debug, Clone)]
pub struct JettonWalletData {
    pub balance: BigUint,
    pub owner_address: MsgAddressInt,
    pub root_address: MsgAddressInt,
    pub wallet_code: Cell,
}

pub fn get_wallet_data(res: VmGetterOutput) -> anyhow::Result<JettonWalletData> {
    if !res.is_ok {
        return Err(WalletContractError::ExecutionFailed {
            exit_code: res.exit_code,
        }
        .into());
    }

    const WALLET_DATA_STACK_ELEMENTS: usize = 4;

    let stack = res.stack;
    if stack.len() == WALLET_DATA_STACK_ELEMENTS {
        let balance = stack[0].as_integer()?.into(0..=u128::MAX)?;

        let mut address_data = stack[1].as_slice()?.clone();
        let owner_address = MsgAddressInt::construct_from(&mut address_data)?;

        let mut data = stack[2].as_slice()?.clone();
        let root_address = MsgAddressInt::construct_from(&mut data)?;

        let wallet_code = stack[3].as_cell()?.clone();

        Ok(JettonWalletData {
            balance: BigUint::from(balance),
            owner_address,
            root_address,
            wallet_code,
        })
    } else {
        Err(WalletContractError::InvalidMethodResultStackSize {
            actual: stack.len(),
            expected: WALLET_DATA_STACK_ELEMENTS,
        }
        .into())
    }
}

#[derive(Error, Debug)]
pub enum WalletContractError {
    #[error("ExecutionFailed (exit_code: {exit_code})")]
    ExecutionFailed { exit_code: i32 },
    #[error("Invalid method result stack size (actual: {actual}, expected {expected})")]
    InvalidMethodResultStackSize { actual: usize, expected: usize },
}
