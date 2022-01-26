use nekoton_abi::{KnownParamTypePlain, PackAbiPlain, UnpackAbiPlain};
use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

pub const TIP3_1_TOKEN_WALLET_CONTRACT_INTERFACE_ID: u32 = 0x2a4ac43e;

/// Get token wallet owner address
///
/// # Type
/// Internal responsible getter
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `owner: address` - token wallet owner address
///
pub fn owner() -> &'static ton_abi::Function {
    declare_function! {
        name: "owner",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("owner", ParamType::Address)],
    }
}

/// Transfer tokens and optionally deploy token wallet for the recipient
///
/// # Type
/// Internal method
///
/// # Inputs
/// * `amount: uint128` - amount of tokens to transfer
/// * `recipient: address` - tokens recipient address
/// * `deployWalletValue: uint128` - how much EVERs to attach to the token wallet deploy
/// * `remainingGasTo: address` - remaining gas receiver
/// * `notify: bool` - notify receiver on incoming transfer
/// * `payload: cell` - arbitrary payload
///
pub fn transfer() -> &'static ton_abi::Function {
    declare_function! {
        name: "transfer",
        inputs: vec![
            Param::new("amount", ParamType::Uint(128)),
            Param::new("recipient", ParamType::Address),
            Param::new("deployWalletValue", ParamType::Uint(128)),
            Param::new("remainingGasTo", ParamType::Address),
            Param::new("notify", ParamType::Bool),
            Param::new("payload", ParamType::Cell),
        ],
        outputs: Vec::new(),
    }
}

/// Transfer tokens using token wallet address
///
/// # Type
/// Internal method
///
/// # Inputs
/// * `amount: uint128` - amount of tokens to transfer
/// * `recipientTokenWallet: address` - recipient token wallet
/// * `remainingGasTo: address` - remaining gas receiver
/// * `notify: bool` - notify receiver on incoming transfer
/// * `payload: cell` - arbitrary payload
///
pub fn transfer_to_wallet() -> &'static ton_abi::Function {
    declare_function! {
        name: "transferToWallet",
        inputs: vec![
            Param::new("amount", ParamType::Uint(128)),
            Param::new("recipientTokenWallet", ParamType::Address),
            Param::new("remainingGasTo", ParamType::Address),
            Param::new("notify", ParamType::Bool),
            Param::new("payload", ParamType::Cell),
        ],
        outputs: Vec::new(),
    }
}

#[derive(Debug, Clone, KnownParamTypePlain, PackAbiPlain, UnpackAbiPlain)]
pub struct AcceptTransferInputs {
    #[abi(uint128)]
    pub amount: u128,
    #[abi(address)]
    pub sender: ton_block::MsgAddressInt,
    #[abi(address, name = "remainingGasTo")]
    pub remaining_gas_to: ton_block::MsgAddressInt,
    #[abi(bool)]
    pub notify: bool,
    #[abi(cell)]
    pub payload: ton_types::Cell,
}

/// Callback for transfer operation
///
/// # Type
/// Internal method
///
/// # Inputs
/// `amount: uint128` - how much tokens to receive
/// `sender: address` - token wallet owner address
///
pub fn accept_transfer() -> &'static ton_abi::Function {
    declare_function! {
        function_id: 0x67A0B95F,
        name: "acceptTransfer",
        inputs: vec![
            Param::new("amount", ParamType::Uint(128)),
            Param::new("sender", ParamType::Address),
            Param::new("remainingGasTo", ParamType::Address),
            Param::new("notify", ParamType::Bool),
            Param::new("payload", ParamType::Cell),
        ],
        outputs: Vec::new(),
    }
}

#[derive(Debug, Clone, KnownParamTypePlain, PackAbiPlain, UnpackAbiPlain)]
pub struct AcceptMintInputs {
    #[abi(uint128)]
    pub amount: u128,
    #[abi(address, name = "remainingGasTo")]
    pub remaining_gas_to: ton_block::MsgAddressInt,
    #[abi(bool)]
    pub notify: bool,
    #[abi(cell)]
    pub payload: ton_types::Cell,
}

/// Accept minted tokens from root
///
/// # Type
/// Internal method
///
/// # Inputs
/// * `amount: uint128` - how much tokens to receive
/// * `remainingGasTo: address` - remaining gas receiver
/// * `notify: bool` - notify receiver on incoming mint
/// * `payload: cell` - arbitrary payload
///
pub fn accept_mint() -> &'static ton_abi::Function {
    declare_function! {
        function_id: 0x4384F298,
        name: "acceptMint",
        inputs: vec![
            Param::new("amount", ParamType::Uint(128)),
            Param::new("remainingGasTo", ParamType::Address),
            Param::new("notify", ParamType::Bool),
            Param::new("payload", ParamType::Cell),
        ],
        outputs: Vec::new(),
    }
}
