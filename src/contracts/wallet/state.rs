use crate::storage::KvStorage;
use crate::transport::Transport;

pub struct WalletState {
    storage: Box<dyn KvStorage>,
    transport: Box<dyn Transport>,
}

impl WalletState {
    pub fn new(storage: Box<dyn KvStorage>, transport: Box<dyn Transport>) -> Self {
        Self { storage, transport }
    }

    pub fn update_cache(&self) {}
}
