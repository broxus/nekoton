use nekoton_abi::num_bigint::BigUint;
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

#[derive(Debug, Clone, UnpackAbi, KnownParamType)]
pub struct RootTokenContractDetails {
    #[abi(with = "bytes_as_string")]
    pub name: String,
    #[abi(with = "bytes_as_string")]
    pub symbol: String,
    #[abi(uint8)]
    pub decimals: u8,
    #[abi(with = "uint256_bytes")]
    pub root_public_key: ton_types::UInt256,
    #[abi(address)]
    pub root_owner_address: ton_block::MsgAddressInt,
    #[abi(with = "uint128_number")]
    pub total_supply: BigUint,
}

pub fn get_details() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        header: [pubkey, time, expire],
        name: "getDetails",
        inputs: vec![Param::new("answerId", ParamType::Uint(32))],
        outputs: vec![Param::new("details", RootTokenContractDetails::param_type())],
    }
}

pub fn get_wallet_address() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        header: [pubkey, time, expire],
        name: "getWalletAddress",
        inputs: vec![
            Param::new("answerId", ParamType::Uint(32)),
            Param::new("walletPublicKey", ParamType::Uint(256)),
            Param::new("ownerAddress", ParamType::Address),
        ],
        outputs: vec![Param::new("address", ParamType::Address)],
    }
}

#[derive(Debug, Clone, UnpackAbiPlain, KnownParamTypePlain)]
pub struct MintInputs {
    #[abi(with = "uint128_number")]
    pub tokens: BigUint,
    #[abi(address)]
    pub to: ton_block::MsgAddressInt,
}

pub fn mint() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        name: "mint",
        inputs: MintInputs::param_type(),
        outputs: Vec::new(),
    }
}

#[derive(Debug, Clone, UnpackAbiPlain, KnownParamTypePlain)]
pub struct TokensBurnedInputs {
    #[abi(with = "uint128_number")]
    pub tokens: BigUint,
    #[abi(with = "uint256_bytes")]
    pub sender_public_key: ton_types::UInt256,
    #[abi(address)]
    pub sender_address: ton_block::MsgAddressInt,
    #[abi(address)]
    pub send_gas_to: ton_block::MsgAddressInt,
    #[abi(address)]
    pub callback_address: ton_block::MsgAddressInt,
    #[abi(cell)]
    pub callback_payload: ton_types::Cell,
}

pub fn tokens_burned() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        name: "tokensBurned",
        inputs: TokensBurnedInputs::param_type(),
        outputs: Vec::new(),
    }
}

#[derive(Debug, Clone, UnpackAbiPlain, KnownParamTypePlain)]
pub struct TransferOwnerInputs {
    #[abi(with = "uint256_bytes")]
    pub root_public_key: ton_types::UInt256,
    #[abi(address)]
    pub root_owner_address: ton_block::MsgAddressInt,
}

pub fn transfer_owner() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_0,
        header: [pubkey, time, expire],
        name: "transferOwner",
        inputs: TransferOwnerInputs::param_type(),
        outputs: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn correct_function_ids() {
        assert_eq!(get_version().input_id, 0x2da94d2f);
        assert_eq!(get_details().input_id, 0x7ff7a47c);
        assert_eq!(get_wallet_address().input_id, 0x069a08f8);
        assert_eq!(mint().input_id, 0x723dc4ce);
        assert_eq!(tokens_burned().input_id, 0x2e2888aa);
        assert_eq!(transfer_owner().input_id, 0x3828261a);
    }
}
