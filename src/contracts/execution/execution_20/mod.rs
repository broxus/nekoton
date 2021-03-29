use ton_executor::{
    BlockchainConfig, ExecutorError, OrdinaryTransactionExecutor, TransactionExecutor,
};
use ton_types::Cell;

struct CompiledContract {
    code: Cell,
    config: BlockchainConfig,
}

impl CompiledContract {
    fn new(code: Cell, config: BlockchainConfig) -> Self {
        Self { code, config }
    }

    fn execute(&self) {
        let executor = OrdinaryTransactionExecutor::new(self.config.clone());
        let mut code = self.code.clone();
        let time = chrono::Utc::now().timestamp() as u32;
        executor.execute(None, &mut code, time, 0, 0, false);
    }
}
