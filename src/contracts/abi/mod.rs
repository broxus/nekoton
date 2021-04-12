use once_cell::sync::OnceCell;
use ton_abi::Contract;

use crate::utils::TrustMe;

const SAFE_MULTISIG_WALLET_ABI: &[u8] = include_bytes!("./SafeMultisigWallet.abi.json");

pub fn safe_multisig_wallet() -> &'static Contract {
    static ABI: OnceCell<Contract> = OnceCell::new();
    ABI.load(SAFE_MULTISIG_WALLET_ABI)
}

const SETCODE_MULTISIG_WALLET_ABI: &[u8] = include_bytes!("./SetcodeMultisigWallet.abi.json");

pub fn setcode_multisig_wallet() -> &'static Contract {
    static ABI: OnceCell<Contract> = OnceCell::new();
    ABI.load(SETCODE_MULTISIG_WALLET_ABI)
}

const TON_TOKEN_WALLET_V3: &[u8] = include_bytes!("./TONTokenWallet.abi.json");

pub fn ton_token_wallet_v3() -> &'static Contract {
    static ABI: OnceCell<Contract> = OnceCell::new();
    ABI.load(TON_TOKEN_WALLET_V3)
}

const ETH_ETH_EVENT: &[u8] = include_bytes!("./EthEvent.abi.json");

pub fn eth_event() -> &'static Contract {
    static ABI: OnceCell<Contract> = OnceCell::new();
    ABI.load(ETH_ETH_EVENT)
}

const ROOT_META: &[u8] = include_bytes!("./RootMeta.abi.json");

pub fn root_meta() -> &'static Contract {
    static ABI: OnceCell<Contract> = OnceCell::new();
    ABI.load(ROOT_META)
}

const TON_TOKEN_WALLET_V2: &[u8] = include_bytes!("./TONTokenWalletV2.abi.json");

pub fn ton_token_wallet_v2() -> &'static Contract {
    static ABI: OnceCell<Contract> = OnceCell::new();
    ABI.load(TON_TOKEN_WALLET_V2)
}

trait OnceCellExt {
    fn load(&self, data: &[u8]) -> &Contract;
}

impl OnceCellExt for OnceCell<Contract> {
    fn load(&self, data: &[u8]) -> &Contract {
        self.get_or_init(|| Contract::load(&mut std::io::Cursor::new(data)).trust_me())
    }
}
