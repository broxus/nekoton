use nekoton_abi::*;
use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

pub fn get_version() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        header: [pubkey, time, expire],
        name: "getVersion",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("version", ParamType::Uint(32))],
    }
}

pub fn balance() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        header: [pubkey, time, expire],
        name: "balance",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("balance", ParamType::Uint(128))],
    }
}

#[derive(Debug, Clone, UnpackAbi, KnownParamType)]
pub struct TokenWalletDetails {
    #[abi(address)]
    pub root_address: ton_block::MsgAddressInt,
    #[abi(with = "uint256_bytes")]
    pub wallet_public_key: ton_types::UInt256,
    #[abi(address)]
    pub owner_address: ton_block::MsgAddressInt,
    #[abi(uint128)]
    pub balance: u128,
    #[abi(address)]
    pub receive_callback: ton_block::MsgAddressInt,
    #[abi(address)]
    pub bounced_callback: ton_block::MsgAddressInt,
    #[abi(bool)]
    pub allow_non_notifiable: bool,
}

pub fn get_details() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        header: [pubkey, time, expire],
        name: "getDetails",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("details", TokenWalletDetails::param_type())],
    }
}

#[derive(Debug, Clone, UnpackAbiPlain, KnownParamTypePlain)]
pub struct AcceptInputs {
    #[abi(uint128)]
    pub tokens: u128,
}

pub fn accept() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        name: "accept",
        inputs: AcceptInputs::param_type(),
        outputs: Vec::new(),
    }
}

#[derive(Debug, Clone, UnpackAbiPlain, KnownParamTypePlain)]
pub struct TransferToRecipientInputs {
    #[abi(with = "uint256_bytes")]
    pub recipient_public_key: ton_types::UInt256,
    #[abi(address)]
    pub recipient_address: ton_block::MsgAddressInt,
    #[abi(uint128)]
    pub tokens: u128,
    #[abi(uint128)]
    pub deploy_grams: u128,
    #[abi(uint128)]
    pub transfer_grams: u128,
    #[abi(address)]
    pub send_gas_to: ton_block::MsgAddressInt,
    #[abi(bool)]
    pub notify_receiver: bool,
    #[abi(cell)]
    pub payload: ton_types::Cell,
}

pub fn transfer_to_recipient() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        name: "transferToRecipient",
        inputs: TransferToRecipientInputs::param_type(),
        outputs: Vec::new(),
    }
}

#[derive(Debug, Clone, UnpackAbiPlain, KnownParamTypePlain)]
pub struct TransferInputs {
    #[abi(address)]
    pub to: ton_block::MsgAddressInt,
    #[abi(uint128)]
    pub tokens: u128,
    #[abi(uint128)]
    pub grams: u128,
    #[abi(address)]
    pub send_gas_to: ton_block::MsgAddressInt,
    #[abi(bool)]
    pub notify_receiver: bool,
    #[abi(cell)]
    pub payload: ton_types::Cell,
}

pub fn transfer() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        name: "transfer",
        inputs: TransferInputs::param_type(),
        outputs: Vec::new(),
    }
}

#[derive(Debug, Clone, UnpackAbiPlain, KnownParamTypePlain)]
pub struct InternalTransferInputs {
    #[abi(uint128)]
    pub tokens: u128,
    #[abi(with = "uint256_bytes")]
    pub sender_public_key: ton_types::UInt256,
    #[abi(address)]
    pub sender_address: ton_block::MsgAddressInt,
    #[abi(address)]
    pub send_gas_to: ton_block::MsgAddressInt,
    #[abi(bool)]
    pub notify_receiver: bool,
    #[abi(cell)]
    pub payload: ton_types::Cell,
}

pub fn internal_transfer() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        name: "internalTransfer",
        inputs: InternalTransferInputs::param_type(),
        outputs: Vec::new(),
    }
}

#[derive(Debug, Clone, UnpackAbiPlain, KnownParamTypePlain)]
pub struct BurnByOwnerInputs {
    #[abi(uint128)]
    pub tokens: u128,
    #[abi(uint128)]
    pub grams: u128,
    #[abi(address)]
    pub send_gas_to: ton_block::MsgAddressInt,
    #[abi(address)]
    pub callback_address: ton_block::MsgAddressInt,
    #[abi(cell)]
    pub callback_payload: ton_types::Cell,
}

pub fn burn_by_owner() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        name: "burnByOwner",
        inputs: BurnByOwnerInputs::param_type(),
        outputs: Vec::new(),
    }
}

#[derive(Debug, Clone, UnpackAbiPlain, KnownParamTypePlain)]
pub struct BurnByRootInputs {
    #[abi(uint128)]
    pub tokens: u128,
    #[abi(address)]
    pub send_gas_to: ton_block::MsgAddressInt,
    #[abi(address)]
    pub callback_address: ton_block::MsgAddressInt,
    #[abi(cell)]
    pub callback_payload: ton_types::Cell,
}

pub fn burn_by_root() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        name: "burnByRoot",
        inputs: BurnByRootInputs::param_type(),
        outputs: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_function_ids() {
        assert_eq!(get_version().input_id, 0x2da94d2f);
        assert_eq!(balance().input_id, 0x4969587f);
        assert_eq!(get_details().input_id, 0x79b25ee1);
        assert_eq!(accept().input_id, 0x0b3fcf57);
        assert_eq!(transfer_to_recipient().input_id, 0x3f10d1ab);
        assert_eq!(transfer().input_id, 0x4bf160e2);
        assert_eq!(internal_transfer().input_id, 0x18d21702);
        assert_eq!(burn_by_owner().input_id, 0x1047c904);
        assert_eq!(burn_by_root().input_id, 0x0c2ff20d);
    }
}
