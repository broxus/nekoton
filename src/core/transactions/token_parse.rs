use ton_abi::ParamType;
use ton_block::Transaction;

use crate::contracts::abi::ton_token_wallet_v2;
use crate::core::models::TokenWalletVersion;
use crate::helpers::abi::FunctionBuilder;
use crate::utils::TrustMe;

use super::models::*;
use crate::contracts::abi;
use ton_types::SliceData;
use std::convert::TryFrom;

pub enum TokenAdditionalInfo {
    V2(TransferFamily),
    V3(TransferFamily)
}

pub fn parse_token_transaction(
    version: TokenWalletVersion,
    tx: &Transaction,
) -> Option<TokenWallet> {
    let slice = tx.in_msg.clone()?.read_struct().ok()?.body()?;
    match version {
        TokenWalletVersion::Tip3v1 => None,
        TokenWalletVersion::Tip3v2 => {token_wallet_parse(slice)}
        TokenWalletVersion::Tip3v3 => {token_wallet_parse(slice)}
    }
}


fn token_wallet_parse(tx: SliceData) -> Option<TokenWallet> {
    let transfer = abi::ton_token_wallet_v3().function("transfer").trust_me();

    if let Ok(a) = transfer.decode_input(tx.clone(), true) {
        let info = Transfer::try_from(a).ok()?;
        return Some(
            TokenWallet::Transfer(
                TransferFamily::Transfer(info)),
        );
    }
    let transfer = abi::ton_token_wallet_v3()
        .function("transferFrom")
        .trust_me();
    if let Ok(a) = transfer.decode_input(tx.clone(), true) {
        let info = TransferFrom::try_from(a).ok()?;
        return Some(
            TokenWallet::Transfer(TransferFamily::TransferFrom(info)),
        );
    }

    let transfer = abi::ton_token_wallet_v3()
        .function("transferToRecipient")
        .trust_me();

    if let Ok(a) = transfer.decode_input(tx.clone(), true) {
        let info = TransferToRecipient::try_from(a).ok()?;
        return Some(
            TokenWallet::Transfer(TransferFamily::TransferToRecipient(info)),
        );
    }

    let transfer = abi::ton_token_wallet_v3()
        .function("internalTransferFrom")
        .trust_me();

    if let Ok(a) = transfer.decode_input(tx.clone(), true) {
        let info = InternalTransferFrom::try_from(a).ok()?;
        return Some(
            TokenWallet::Transfer(TransferFamily::InternalTransferFrom(info)),
        );
    }

    let tokens_bounced = FunctionBuilder::new("tokensBouncedCallback")
        .in_arg("token_wallet", ParamType::Address)
        .in_arg("token_root", ParamType::Address)
        .in_arg("amount", ParamType::Uint(128))
        .in_arg("bounced_from", ParamType::Address)
        .in_arg("updated_balance", ParamType::Uint(128))
        .build();

    if let Ok(a) = tokens_bounced.decode_input(tx.clone(), true) {
        let info = BounceCallback::try_from(a).ok()?;
        return Some(TokenWallet::TokensBounced(info));
    };

    let mint = FunctionBuilder::new("accept")
        .in_arg("tokens", ParamType::Uint(128))
        .build();

    if let Ok(a) = mint.decode_input(tx.clone(), true) {
        let info = Mint::try_from(a).ok()?;
        return Some(TokenWallet::TokenMint(info));
    }

    let token_swap_back = abi::ton_token_wallet_v3()
        .function("burnByOwner")
        .trust_me();
    if let Ok(a) = token_swap_back.decode_input(tx, true) {
        let info = TokenSwapBack::try_from(a).ok()?;
        return Some(TokenWallet::TokenSwapBack(info));
    }
    None
}