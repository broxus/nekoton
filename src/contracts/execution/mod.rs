use anyhow::Error;
use ton_block::{AccountStorage, AccountStuff, MsgAddrStd, MsgAddressInt};
use ton_sdk::{Contract, ContractImage};

use tvm::call;

// use ton_abi::Contract;
use crate::utils::NoFailure;

mod labs;
mod tvm;

struct LocalExecutor {
    contract: ton_abi::Contract,
}

impl LocalExecutor {
    pub fn new(abi: &str) -> Result<Self, Error> {
        let reader = std::io::Cursor::new(abi);
        let contract = ton_sdk::AbiContract::load(reader).convert()?;
        contract.function("kek").convert()?;
        Ok(Self { contract })
    }
    fn calculate_fee(&self) {
        let astuff = AccountStuff {
            addr: MsgAddressInt::AddrStd(MsgAddrStd::default()),
            storage_stat: Default::default(),
            storage: AccountStorage::default(),
        };
    }
}
