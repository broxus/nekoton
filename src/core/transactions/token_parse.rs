use ton_abi::ParamType;
use ton_block::Transaction;

use crate::contracts::abi::ton_token_wallet_v2;
use crate::core::models::TokenWalletVersion;
use crate::helpers::abi::FunctionBuilder;
use crate::utils::TrustMe;

use super::models;

pub enum TokenAdditionalInfo {}

pub fn parse_token_transaction(
    version: TokenWalletVersion,
    tx: &Transaction,
) -> Option<TokenAdditionalInfo> {
    match version {
        TokenWalletVersion::Tip3v1 => None,
        TokenWalletVersion::Tip3v2 => {}
        TokenWalletVersion::Tip3v3 => {}
    }
}

fn parse_tip3v2(tx: &Transaction) {
    let burn = ton_token_wallet_v2().function("burnByOwner").trust_me();

    let transfer = ton_token_wallet_v2()
        .function("transferToRecipient")
        .trust_me();
    let transfer = ton_token_wallet_v2().function("transfer").trust_me();
    let transfer = ton_token_wallet_v2().function("transferFrom").trust_me();
    let transfer = ton_token_wallet_v2()
        .function("internalTransfer")
        .trust_me();
    let transfer = ton_token_wallet_v2()
        .function("internalTransferFrom")
        .trust_me();

    let tokens_bounced = FunctionBuilder::new("tokensBouncedCallback")
        .in_arg("token_wallet", ParamType::Address)
        .in_arg("token_root", ParamType::Address)
        .in_arg("amount", ParamType::Uint(128))
        .in_arg("bounced_from", ParamType::Address)
        .in_arg("updated_balance", ParamType::Uint(128))
        .build();

    let mint = FunctionBuilder::new("accept")
        .in_arg("tokens", ParamType::Uint(128))
        .build();

    let token_swap_back = ton_token_wallet_v2().function("burnByOwner").trust_me();
}
