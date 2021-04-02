use ton_types::Cell;

use crate::utils::TrustMe;

pub fn safe_multisig_wallet() -> Cell {
    ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(SAFE_MULTISIG_WALLET_CODE))
        .trust_me()
}

pub fn safe_multisig_wallet_24h() -> Cell {
    ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(SAFE_MULTISIG_WALLET24H_CODE))
        .trust_me()
}

pub fn setcode_multisig_wallet() -> Cell {
    ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(SETCODE_MULTISIG_WALLET_CODE))
        .trust_me()
}

pub fn surf_wallet() -> Cell {
    ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(SURF_WALLET_CODE)).trust_me()
}

pub fn wallet_v3() -> Cell {
    ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(WALLET_V3_CODE)).trust_me()
}

const SAFE_MULTISIG_WALLET_CODE: &[u8] = include_bytes!("./SafeMultisigWallet.tvc");
const SAFE_MULTISIG_WALLET24H_CODE: &[u8] = include_bytes!("./SafeMultisigWallet24h.tvc");
const SETCODE_MULTISIG_WALLET_CODE: &[u8] = include_bytes!("./SetcodeMultisigWallet.tvc");
const SURF_WALLET_CODE: &[u8] = include_bytes!("./Surf.tvc");
const WALLET_V3_CODE: &[u8] = include_bytes!("./wallet_code.boc");
