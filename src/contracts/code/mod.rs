use ton_types::Cell;

use crate::utils::TrustMe;

macro_rules! declare_tvc {
    ($($contract:ident => $source:literal ($const_bytes:ident)),*$(,)?) => {$(
        const $const_bytes: &[u8] = include_bytes!($source);

        pub fn $contract() -> Cell {
            load($const_bytes)
        }
    )*};
}

declare_tvc! {
    safe_multisig_wallet => "./SafeMultisigWallet.tvc" (SAFE_MULTISIG_WALLET_CODE),
    safe_multisig_wallet_24h => "./SafeMultisigWallet24h.tvc" (SAFE_MULTISIG_WALLET24H_CODE),
    setcode_multisig_wallet => "./SetcodeMultisigWallet.tvc" (SETCODE_MULTISIG_WALLET_CODE),
    surf_wallet => "./Surf.tvc" (SURF_WALLET_CODE),
    wallet_v3 => "./wallet_code.boc" (WALLET_V3_CODE),
    root_meta => "./RootMeta.tvc" (ROOT_META),
}

fn load(data: &[u8]) -> Cell {
    ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(data)).trust_me()
}
