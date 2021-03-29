use crate::transport::Transport;

use super::wallet::state::WalletState;

mod state;

pub struct Wallet {
    state: WalletState,
}
