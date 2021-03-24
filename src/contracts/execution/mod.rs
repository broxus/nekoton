use anyhow::Error;
use ton_block::AccountStuff;
use ton_sdk::{Contract, ContractImage};

use tvm::call;

// use ton_abi::Contract;
use crate::utils::NoFailure;

mod tvm;

struct LocalExecutor {
    contract: ton_abi::Contract,
}

impl LocalExecutor {
    pub fn new(abi: &str) -> Result<Self, Error> {
        let reader = std::io::Cursor::new(abi);
        let contract = ton_sdk::AbiContract::load(reader).convert()?;
        contract.function("kek").convert()?.Ok(Self { contract })
    }
    fn calculate_fee(&self) {
        let astuff = AccountStuff {
            addr: self.contract,
            storage_stat: Default::default(),
            storage: Default::default(),
        };
        tvm::call()
    }
}
