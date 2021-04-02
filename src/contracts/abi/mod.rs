use once_cell::sync::OnceCell;
use ton_abi::Contract;

use crate::utils::TrustMe;

pub fn safe_multisig_wallet() -> &'static Contract {
    static ABI: OnceCell<Contract> = OnceCell::new();
    ABI.get_or_init(|| {
        Contract::load(&mut std::io::Cursor::new(SAFE_MULTISIG_WALLET_ABI)).trust_me()
    })
}

pub fn setcode_multisig_wallet() -> &'static Contract {
    static ABI: OnceCell<Contract> = OnceCell::new();
    ABI.get_or_init(|| {
        Contract::load(&mut std::io::Cursor::new(SETCODE_MULTISIG_WALLET_ABI)).trust_me()
    })
}

pub fn ton_token_wallet() -> &'static Contract {
    static ABI: OnceCell<Contract> = OnceCell::new();
    ABI.get_or_init(|| Contract::load(&mut std::io::Cursor::new(TON_TOKKEN_WALLET)).trust_me())
}

pub fn eth_event() -> &'static Contract {
    static ABI: OnceCell<Contract> = OnceCell::new();
    ABI.get_or_init(|| Contract::load(&mut std::io::Cursor::new(ETH_ETH_EVENT)).trust_me())
}



const SAFE_MULTISIG_WALLET_ABI: &[u8] = include_bytes!("./SafeMultisigWallet.abi.json");
const SETCODE_MULTISIG_WALLET_ABI: &[u8] = include_bytes!("./SetcodeMultisigWallet.abi.json");
const TON_TOKKEN_WALLET: &[u8] = include_bytes!("./TONTokenWallet.abi.json");
const ETH_ETH_EVENT: &[u8] = include_bytes!("./EthEvent.abi.json");
