use nekoton_abi::{KnownParamTypePlain, PackAbiPlain, UnpackAbiPlain};
use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

pub const TIP3_1_ROOT_TOKEN_CONTRACT_INTERFACE_ID: u32 = 0x0b1fd263;

/// Get root owner
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
///
/// # Outputs
/// * `owner: address` - owner wallet address
///
pub fn root_owner() -> &'static ton_abi::Function {
    declare_function! {
        name: "rootOwner",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("rootOwner", ParamType::Address)],
    }
}

/// Derive TokenWallet address from owner address
///
/// # Type
/// Responsible getter method
///
/// # Inputs
/// * `answerId: uint32` - responsible answer id
/// * `owner: address` - owner address
///
/// # Outputs
/// * `walletAddress: address` - owner wallet address
///
pub fn wallet_of() -> &'static ton_abi::Function {
    declare_function! {
        name: "walletOf",
        inputs: vec![
            Param::new("answerId", ParamType::Uint(32)),
            Param::new("owner", ParamType::Address),
        ],
        outputs: vec![Param::new("walletAddress", ParamType::Address)],
    }
}

#[derive(Debug, Clone, KnownParamTypePlain, PackAbiPlain, UnpackAbiPlain)]
pub struct AcceptBurnInputs {
    #[abi(uint128)]
    pub amount: u128,
    #[abi(address, name = "walletOwner")]
    pub wallet_owner: ton_block::MsgAddressInt,
    #[abi(address, name = "remainingGasTo")]
    pub remaining_gas_to: ton_block::MsgAddressInt,
    #[abi(address, name = "callbackTo")]
    pub callback_to: ton_block::MsgAddressInt,
    #[abi(cell)]
    pub payload: ton_types::Cell,
}

/// Called by token wallet on burn
///
/// # Type
/// Internal method
///
/// # Inputs
/// * `amount: uint128` - amount of tokens
/// * `walletOwner: address` - token wallet owner
/// * `remainingGasTo: address` - address where to send excess gas
/// * `callbackTo: address` - address where to send callback
/// * `payload: cell` - arbitrary payload
///
pub fn accept_burn() -> &'static ton_abi::Function {
    declare_function! {
        function_id: 0x192B51B1,
        name: "acceptBurn",
        inputs: vec![
            Param::new("amount", ParamType::Uint(128)),
            Param::new("walletOwner", ParamType::Address),
            Param::new("remainingGasTo", ParamType::Address),
            Param::new("callbackTo", ParamType::Address),
            Param::new("payload", ParamType::Cell),
        ],
        outputs: Vec::new(),
    }
}

/// Mint tokens to recipient with deploy wallet optional
///
/// # Type
/// Internal method
///
/// # Inputs
/// * `amount: uint128` - how much tokens to mint
/// * `recipient: address` - minted tokens owner address
/// * `deployWalletValue: uint128` - how much EVERs to send to wallet on deployment
/// * `remainingGasTo: address` - address where to send excess gas
/// * `notify: bool` - whether to notify the recipient
/// * `payload: cell` - arbitrary payload
///
pub fn mint() -> &'static ton_abi::Function {
    declare_function! {
        name: "mint",
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

/// Deploy new TokenWallet
///
/// # Type
/// Internal responsible method
///
/// # Inputs
/// * `owner: address` - token wallet owner address
/// * `deployWalletValue: uint128` - amount of EVERs attached to the callback
///
pub fn deploy_wallet() -> &'static ton_abi::Function {
    declare_function! {
        name: "deployWallet",
        inputs: vec![
            Param::new("owner", ParamType::Address),
            Param::new("deployWalletValue", ParamType::Uint(128)),
        ],
        outputs: vec![Param::new("address", ParamType::Address)],
    }
}
