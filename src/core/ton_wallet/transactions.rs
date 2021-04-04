use std::convert::TryFrom;

use ton_abi::{ParamType, TokenValue};
use ton_block::Transaction;

use super::models::*;
use crate::contracts::abi;
use crate::helpers::abi::{FunctionBuilder, FunctionExt};
use crate::utils::*;

//todo normal name
fn main_wallet_parse(tx: &Transaction) -> Option<TransactionAdditionalInfo> {
    let wallet_deploy = FunctionBuilder::new("notifyWalletDeployed")
        .in_arg("root", ParamType::Address)
        .build();
    if let Ok(a) = wallet_deploy.parse(tx) {
        let address = match &a.get(0)?.value {
            TokenValue::Address(ad) => TransactionAdditionalInfo::TokenWalletDeployed(ad.clone()),
            _ => TransactionAdditionalInfo::RegularTransaction,
        };
        return Some(address);
    };

    todo!()
    // Ok(())
}

fn token_wallet_parse(tx: &Transaction) -> Option<TransactionAdditionalInfo> {
    let transfer = abi::ton_token_wallet().function("transferFrom").trust_me();

    if let Ok(a) = transfer.parse(tx) {
        let info = Transfer::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokenTransfer(
            TransferFamily::Transfer(info),
        ));
    }

    if let Ok(a) = transfer.parse(tx) {
        let info = TransferFrom::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokenTransfer(
            TransferFamily::TransferFrom(info),
        ));
    }

    if let Ok(a) = transfer.parse(tx) {
        let info = TransferToRecipient::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokenTransfer(
            TransferFamily::TransferToRecipient(info),
        ));
    }

    if let Ok(a) = transfer.parse(tx) {
        let info = InternalTransferFrom::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokenTransfer(
            TransferFamily::InternalTransferFrom(info),
        ));
    }

    let tokens_bounced = FunctionBuilder::new("tokensBouncedCallback")
        .in_arg("token_wallet", ParamType::Address)
        .in_arg("token_root", ParamType::Address)
        .in_arg("amount", ParamType::Uint(128))
        .in_arg("bounced_from", ParamType::Address)
        .in_arg("updated_balance", ParamType::Uint(128))
        .build();

    if let Ok(a) = tokens_bounced.parse(tx) {
        let info = BounceCallback::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokensBounced(info));
    };

    let mint = FunctionBuilder::new("mint")
        .in_arg("tokens", ParamType::Uint(128))
        .in_arg("to", ParamType::Address)
        .build();

    if let Ok(a) = mint.parse(&tx) {
        let info = Mint::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokenMint(info));
    }

    let token_swap_back = abi::ton_token_wallet().function("burnByOwner").trust_me();
    if let Ok(a) = token_swap_back.parse(tx) {
        let info = TokenSwapBack::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokenSwapBack(info));
    }

    Some(TransactionAdditionalInfo::RegularTransaction)
}

fn event_parse(tx: &Transaction) -> Option<TransactionAdditionalInfo> {
    let eth_event = FunctionBuilder::new("notifyEthereumEventStatusChanged")
        .in_arg("EthereumEventStatus", ParamType::Uint(8))
        .build();
    if let Ok(a) = eth_event.parse(tx) {
        let info = EthereumStatusChanged::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::EthEventStatusChanged(info));
    }
    let ton_event = FunctionBuilder::new("notifyTonEventStatusChanged")
        .in_arg("TonEventStatus", ParamType::Uint(8))
        .build();
    if let Ok(a) = ton_event.parse(tx) {
        let info = TonEventStatus::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TonEventStatusChanged(info));
    }

    None
}

pub fn parse_additional_info(
    tx: &Transaction,
    ctx: ParsingContext,
) -> Option<TransactionAdditionalInfo> {
    match ctx {
        ParsingContext::MainWallet => main_wallet_parse(tx),
        ParsingContext::TokenWallet => token_wallet_parse(tx),
        ParsingContext::Event => event_parse(tx),
    }
}
