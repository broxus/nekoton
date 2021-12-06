use once_cell::race::OnceBox;
use ton_abi::Contract;

macro_rules! declare_abi {
    ($($contract:ident => $source:literal),*$(,)?) => {$(
        pub fn $contract() -> &'static Contract {
            static ABI: OnceBox<Contract> = OnceBox::new();
            ABI.get_or_init(|| {
                Box::new(Contract::load(&mut std::io::Cursor::new(include_bytes!($source))).expect("Trust me"))
            })
        }
    )*};
}

declare_abi! {
    depool_v3_participant => "./DePoolV3Participant.abi.json",
    safe_multisig_wallet => "./SafeMultisigWallet.abi.json",
    setcode_multisig_wallet => "./SetcodeMultisigWallet.abi.json",
    bridge_multisig_wallet => "./BridgeMultisigWallet.abi.json",
    wallet_notifications => "./WalletNotifications.abi.json",
    root_meta => "./RootMeta.abi.json",
    ton_token_wallet_v4 => "./TONTokenWalletV4.abi.json",
    root_token_contract_v4 => "./RootTokenContractV4.abi.json",
}
