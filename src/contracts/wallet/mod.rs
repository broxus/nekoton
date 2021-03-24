use cached::proc_macro::cached;
use ton_block::Message;

use crate::transport::Transport;

use super::wallet::state::WalletState;

mod state;

pub struct Wallet {
    state: WalletState,
}

// impl Wallet {
//     fn new(transport: &dyn Transport) {}
//
//     pub fn send_message(&self, message: &Message) {
//         // self.transport.send_message(message)
//     }
//
//     pub fn get_state(&self) -> &WalletState {
//         &self.state
//     }
//
//     pub fn update_state(&mut self) -> &WalletState {
//         &self.state
//     }
// }
