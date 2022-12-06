use ton_types::Cell;

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
    setcode_multisig_wallet_24h => "./SetcodeMultisigWallet24h.tvc" (SETCODE_MULTISIG_WALLET24H_CODE),
    bridge_multisig_wallet => "./BridgeMultisigWallet.tvc" (BRIDGE_MULTISIG_WALLET_CODE),
    multisig2 => "./Multisig2.tvc" (MULTISIG2_CODE),
    multisig2_1 => "./Multisig2_1.tvc" (MULTISIG2_1_CODE),
    surf_wallet => "./Surf.tvc" (SURF_WALLET_CODE),
    wallet_v3 => "./wallet_v3_code.boc" (WALLET_V3_CODE),
    highload_wallet_v2 => "./highload_wallet_v2_code.boc" (HIGHLOAD_WALLET_V2_CODE),
    ever_wallet => "./ever_wallet_code.boc" (EVER_WALLET_CODE),
}

fn load(mut data: &[u8]) -> Cell {
    ton_types::deserialize_tree_of_cells(&mut data).expect("Trust me")
}
