use once_cell::sync::OnceCell;
use ton_abi::Contract;

macro_rules! declare_abi {
    ($($contract:ident => $source:literal),*$(,)?) => {$(
        pub fn $contract() -> &'static Contract {
            static ABI: OnceCell<Contract> = OnceCell::new();
            ABI.load(include_bytes!($source))
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

trait OnceCellExt {
    fn load(&self, data: &[u8]) -> &Contract;
}

impl OnceCellExt for OnceCell<Contract> {
    fn load(&self, data: &[u8]) -> &Contract {
        self.get_or_init(|| Contract::load(&mut std::io::Cursor::new(data)).expect("Trust me"))
    }
}
