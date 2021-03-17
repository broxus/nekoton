use anyhow::Result;

use crate::transport::models::*;
use crate::transport::Transport;

pub struct TonInterface {
    transport: Box<dyn Transport>,
}

impl TonInterface {
    pub fn new(transport: Box<dyn Transport>) -> Self {
        Self { transport }
    }

    pub async fn get_masterchain_info(&self) -> Result<LastBlockIdExt> {
        self.transport.get_masterchain_info().await
    }
}
