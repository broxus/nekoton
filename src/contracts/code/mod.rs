use ton_types::Cell;

use crate::utils::TrustMe;

const SAFE_MULTISIG_WALLET_CODE: &[u8] = include_bytes!("./SafeMultisigWallet.tvc");

pub fn safe_multisig_wallet() -> Cell {
    load(SAFE_MULTISIG_WALLET_CODE)
}

const SAFE_MULTISIG_WALLET24H_CODE: &[u8] = include_bytes!("./SafeMultisigWallet24h.tvc");

pub fn safe_multisig_wallet_24h() -> Cell {
    load(SAFE_MULTISIG_WALLET24H_CODE)
}

const SETCODE_MULTISIG_WALLET_CODE: &[u8] = include_bytes!("./SetcodeMultisigWallet.tvc");

pub fn setcode_multisig_wallet() -> Cell {
    load(SETCODE_MULTISIG_WALLET_CODE)
}

const SURF_WALLET_CODE: &[u8] = include_bytes!("./Surf.tvc");

pub fn surf_wallet() -> Cell {
    load(SURF_WALLET_CODE)
}

const WALLET_V3_CODE: &[u8] = include_bytes!("./wallet_code.boc");

pub fn wallet_v3() -> Cell {
    load(WALLET_V3_CODE)
}

const ROOT_META: &[u8] = include_bytes!("./RootMeta.tvc");

pub fn root_meta() -> Cell {
    load(ROOT_META)
}

fn load(data: &[u8]) -> Cell {
    ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(data)).trust_me()
}
