use std::convert::TryFrom;

use ton_abi::{ParamType, TokenValue};
use ton_block::Transaction;
use ton_types::SliceData;

use crate::contracts::abi;
use crate::contracts::abi::safe_multisig_wallet;
use crate::helpers::abi::{FunctionBuilder, FunctionExt};
use crate::utils::*;

use super::models::*;

//todo normal name
fn main_wallet_parse(tx: SliceData) -> Option<TransactionAdditionalInfo> {
    let wallet_deploy = FunctionBuilder::new("notifyWalletDeployed")
        .in_arg("root", ParamType::Address)
        .build();
    if let Ok(a) = wallet_deploy.decode_input(tx, true) {
        let address = match &a.get(0)?.value {
            TokenValue::Address(ad) => TransactionAdditionalInfo::TokenWalletDeployed(ad.clone()),
            _ => return None,
        };
        return Some(address);
    };

    Some(TransactionAdditionalInfo::RegularTransaction)
}

fn token_wallet_parse(tx: SliceData) -> Option<TransactionAdditionalInfo> {
    let transfer = abi::ton_token_wallet().function("transfer").trust_me();

    if let Ok(a) = transfer.decode_input(tx.clone(), true) {
        let info = Transfer::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokenTransfer(
            TransferFamily::Transfer(info),
        ));
    }
    let transfer = abi::ton_token_wallet().function("transferFrom").trust_me();
    if let Ok(a) = transfer.decode_input(tx.clone(), true) {
        let info = TransferFrom::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokenTransfer(
            TransferFamily::TransferFrom(info),
        ));
    }

    let transfer = abi::ton_token_wallet()
        .function("transferToRecipient")
        .trust_me();

    if let Ok(a) = transfer.decode_input(tx.clone(), true) {
        let info = TransferToRecipient::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokenTransfer(
            TransferFamily::TransferToRecipient(info),
        ));
    }

    let transfer = abi::ton_token_wallet()
        .function("internalTransferFrom")
        .trust_me();

    if let Ok(a) = transfer.decode_input(tx.clone(), true) {
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

    if let Ok(a) = tokens_bounced.decode_input(tx.clone(), true) {
        let info = BounceCallback::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokensBounced(info));
    };

    let mint = FunctionBuilder::new("accept")
        .in_arg("tokens", ParamType::Uint(128))
        .build();

    if let Ok(a) = mint.decode_input(tx.clone(), true) {
        let info = Mint::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokenMint(info));
    }

    let token_swap_back = abi::ton_token_wallet().function("burnByOwner").trust_me();
    if let Ok(a) = token_swap_back.decode_input(tx, true) {
        let info = TokenSwapBack::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TokenSwapBack(info));
    }
    Some(TransactionAdditionalInfo::RegularTransaction)
}

fn event_parse(tx: SliceData) -> Option<TransactionAdditionalInfo> {
    let eth_event = FunctionBuilder::new("notifyEthereumEventStatusChanged")
        .in_arg("EthereumEventStatus", ParamType::Uint(8))
        .build();

    if let Ok(a) = eth_event.decode_input(tx.clone(), true) {
        let info = EthereumStatusChanged::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::EthEventStatusChanged(info));
    }
    let ton_event = FunctionBuilder::new("notifyTonEventStatusChanged")
        .in_arg("TonEventStatus", ParamType::Uint(8))
        .build();
    if let Ok(a) = ton_event.decode_input(tx, true) {
        let info = TonEventStatus::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::TonEventStatusChanged(info));
    }

    Some(TransactionAdditionalInfo::RegularTransaction)
}

pub fn parse_additional_info(
    tx: &Transaction,
    ctx: ParsingContext,
) -> Option<TransactionAdditionalInfo> {
    let body = tx.in_msg.clone()?.read_struct().ok()?.body()?;
    match ctx {
        ParsingContext::MainWallet => main_wallet_parse(body),
        ParsingContext::TokenWallet => token_wallet_parse(body),
        ParsingContext::Event => event_parse(body),
        ParsingContext::Multisig => multisig_parse(body, tx),
    }
}

fn multisig_parse(data: SliceData, tx: &Transaction) -> Option<TransactionAdditionalInfo> {
    let send = safe_multisig_wallet()
        .function("sendTransaction")
        .trust_me();

    if let Ok(a) = send.decode_input(data.clone(), false) {
        dbg!(&a);
        let info = SendTransaction::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::MultisigSendTransaction(info));
    }

    let confirm = safe_multisig_wallet()
        .function("confirmTransaction")
        .trust_me();

    if let Ok(a) = confirm.decode_input(data.clone(), false) {
        dbg!(&a);
        let info = ConfirmTransaction::try_from(a).ok()?;
        return Some(TransactionAdditionalInfo::MultisigConfirmTransaction(info));
    }

    let submit = safe_multisig_wallet()
        .function("submitTransaction")
        .trust_me();

    if let Ok(a) = submit.decode_input(data, false) {
        dbg!(&a);
        let out = submit.parse(tx).ok()?;
        let info = SubmitTransaction::try_from((a, out)).ok()?;
        return Some(TransactionAdditionalInfo::MultisigSubmitTransaction(info));
    }

    Some(TransactionAdditionalInfo::RegularTransaction)
}

#[cfg(test)]
mod test {
    use ton_block::MsgAddress::AddrStd;
    use ton_block::{Deserializable, MsgAddrStd, Serializable, Transaction};

    use crate::core::ton_wallet::models::{
        EthereumStatusChanged, ParsingContext, TonEventStatus, TransactionAdditionalInfo,
        TransferFamily,
    };
    use crate::core::ton_wallet::transactions::parse_additional_info;

    #[test]
    fn test_main_wallet_parse() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAATAAA7F44lhmAlE+maVfor4IVhRpx85Rp9WiWXdVjnfvK8k4e0AAALc5peDsFNAtcF1BRBGfRP73+ljNPUUc+ir7FmHntIcbeh/ba28gAAC3OZS2ZBYGofQAABQgSAMCAQAVBECIicQJoBh6EgIAgnIIhWuBGHA/f3IsyBPHr57C3d7pcU83NmIoz5CkFu+Hsn742ILtpOsOCyUw6fEN9VwMZzJ8dj6MuR/kKlztR9sKAQGgBAD3aAHILrQNhiymjQB0/Pw/ubdxFv4FXRIQhcVcOMZMH8eJ5wAjiWGYCUT6ZpV+ivghWFGnHzlGn1aJZd1WOd+8ryTh7QicQAYUWGAAABbnNEILiMDUPm4kKd2bwA7tPzMWNNSaXaK1RvRlLdSIlIehh8LvndIgPP8XtYTj2A==").unwrap();
        let got = parse_additional_info(&tx, ParsingContext::MainWallet).unwrap();
        let expected =
            TransactionAdditionalInfo::TokenWalletDeployed(AddrStd(MsgAddrStd::with_address(
                None,
                0,
                hex::decode("eed3f331634d49a5da2b546f4652dd4889487a187c2ef9dd2203cff17b584e3d")
                    .unwrap()
                    .into(),
            )));
        assert_eq!(expected, got)
    }

    #[test]
    fn test_transfer() {
        let tx = Transaction::construct_from_base64(
            "te6ccgECCgEAAlwAA7V8muz7krT7DzqKmhdUz154mm9p5nMARjF1SYKfXOt/e7AAALetrfj4FCLRCVIzBq1boO8A7VCmzswWyg2fn0LyTnXKERMW4pBwAAC3oG+pDDYGs9IQADRvEgVIBAMBASkEi56JB3NZQBBuaXQOAYKLCBhRYYICAJ5DsIwehIAAAAAA4AAAAMMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIJygCoUDT0DVWzws7litK//Fuk0c79TXHyoT4iGjU12YI+nvQ9RnqsFJbDbfmh68F1Zv769vnFhBumtE6Brk+lb6wIB4AcFAQHfBgD5WAGTXZ9yVp9h51FTQuqZ688TTe08zmAIxi6pMFPrnW/vdwATQApsl8kQWA4D1gdrW3bYtm2CFTJuVhuilnM7QRLY3FB1K1yABhRYYAAAFvW1vx8EwNZ6Qn////+l+LBxQAya7PuStPsPOoqaF1TPXniab2nmcwBGMXVJgsABsWgAmgBTZL5IgsBwHrA7Wtu2xbNsEKmTcrDdFLOZ2giWxuMAMmuz7krT7DzqKmhdUz154mm9p5nMARjF1SYKfXOt/e7QdzWUAAYpKIoAABb1tSaIhMDWeirACAHNS/Fg4oAZNdn3JWn2HnUVNC6pnrzxNN7TzOYAjGLqkwU+udb+92AAAAAAAAAAAAAAAAATEtAAAAAAAAAAAAAAAAAAAAAAEAE0AKbJfJEFgOA9YHa1t22LZtghUyblYbopZzO0ES2NxQkAAA==",
        )
            .unwrap();
        if let TransactionAdditionalInfo::TokenTransfer(a) =
            parse_additional_info(&tx, ParsingContext::TokenWallet).unwrap()
        {
            if let TransferFamily::Transfer(_) = a {
            } else {
                panic!()
            }
        } else {
            panic!()
        }
    }

    #[test]
    fn test_send_transfer_to_recipient() {
        let tx = Transaction::construct_from_base64(
            "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",
        )
            .unwrap();
        if let TransactionAdditionalInfo::TokenTransfer(a) =
            parse_additional_info(&tx, ParsingContext::TokenWallet).unwrap()
        {
            if let TransferFamily::TransferToRecipient(_) = a {
            } else {
                panic!()
            }
        } else {
            panic!()
        }
    }

    #[test]
    fn test_swap() {
        let tx = Transaction::construct_from_base64("te6ccgECDQEAAx4AA7V/AxqO0U7QTnYewCYNWriQfk3gBkNp5RAP5xRZRXYCQlAAAK8wDBUYEgZhXilMhb8uwySppSot4mIjr0gv3SETJXkSpo1fNtPQAACvL/vetDYFZ2wQADR//SVoBQQBAhcETQkHc1lAGH5JaxEDAgBvyZRshEw2dnwAAAAAAAQAAgAAAALltNr4qYJCC5/34YbNvyKcqgqDBCXdRgOzhnR40LLkaEEQQRQAnkfA7B6EgAAAAAAAAAABbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgnJyFRYUCdbm/iIPBBrBh1nQvDRUv4iVZ/TPXsafdMGq7iwcTZXDAFF+tOJ0kZZV41JVZ/IFqG20VsHpSYsLRlDmAgHgCgYBAd8HAbFoAeBjUdop2gnOw9gEwatXEg/JvADIbTyiAfziiyiuwEhLADOcXDcMUS0fCqCF6CrhQZyn2MQ4TEQF7IDBOoLlzsWDUHLFXNQGNnbSAAAV5gGCowTArO2CwAgB7S4oiKoAAAAAAAAAAAAAAAAAmJaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAFSQopo5GzW/93YKmR1LWu54uMvkRuBqK8b9KUgFxRnlwAqSFFNHI2a3/u7BUyOpa13PFxl8iNwNRXjfpSkAuKM8uCQFDgAvpSKEmcdsAU50DME0ul92s65jErkbosgMW7ZfKyelfEAwBsWgBUkKKaORs1v/d2CpkdS1rueLjL5EbgaivG/SlIBcUZ5cAPAxqO0U7QTnYewCYNWriQfk3gBkNp5RAP5xRZRXYCQlQdzWUAAYsZKwAABXmAMuIBMCs7W7ACwHNEEfJBAAAAAAAAAAAAAAAAACYloAAAAAAAAAAAAAAAAAAAAAAgBUkKKaORs1v/d2CpkdS1rueLjL5EbgaivG/SlIBcUZ5cAF9KRQkzjtgCnOgZgml0vu1nXMYlcjdFkBi3bL5WT0r4gwAKGLH29AUH5aUHpmCISLU2U5gJYC7").unwrap();

        if let TransactionAdditionalInfo::TokenSwapBack(_) =
            parse_additional_info(&tx, ParsingContext::TokenWallet).unwrap()
        {
            ()
        } else {
            panic!()
        };
    }

    #[test]
    fn test_mint() {
        let tx = Transaction::construct_from_base64("te6ccgECBwEAAaMAA7V/Dx4joMaXoc3RFiyAn6o7n4HT55z5/QGPim3CCNJXQXAAAK8vTVj4NVj26LQJ+AavyN1HTyfjsnB1V8MYazh2SAaGUfKitkNwAACvL01Y+BYFZ1BAABRzL58IBQQBAhMECOYloBhzL58RAwIAW8AAAAAAAAAAAAAAAAEtRS2kSeULjPfdJ4YfFGEir+G1RruLcPyCFvDGFBOfjgQAnETpaJxAAAAAAAAAAADmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCcmGLc3puHpvUqy9khm0IOdhMB4DZAuyNlJTJCkg0wvMOh6b7MBQnENOWWqV8wO0KnzyqzAm1eeuCWS1jgX4RNrUBAaAGANdoAEC3zK80W70FBnMN7CWF5ai6t7ZNfr6N19g9kzzkIx83ADw8eI6DGl6HN0RYsgJ+qO5+B0+ec+f0Bj4ptwgjSV0FzmJaAAYUWGAAABXl6TENBsCs6fAFn+ergAAAAAAAAAAN4Lazp2QAAEA=").unwrap();

        if let TransactionAdditionalInfo::TokenMint(_) =
            dbg!(parse_additional_info(&tx, ParsingContext::TokenWallet).unwrap())
        {
            ()
        } else {
            panic!()
        };
    }

    #[test]
    fn test_notify_in_progress() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAARIAA7F3Z4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCAAACgpY0FkF0icFNiz9eyMoHQj/XjOgvfd/Ty/FCTLIWVObMZeWYygAAAoKVP/JBYFZCYQABQgSAMCAQAXBECIwGGoCaAYehICAIJyfS8JL8YlmU0DmZFQVw8vxQ/7HiHzKY43/AS+wp7M2ylauXc4qj/KSRi2zF7A/86IuQtXzsWopEYjhgirgz9e7AEBoAQAuWgANCX2CqQaEevZ1UVg2Lqddhy1GwOCKNcFg+tItZwPrSsAHZ4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCMBhqABhRYYAAABQUsDJ8EwKyEtCQz2A0AQA==").unwrap();

        if let TransactionAdditionalInfo::TonEventStatusChanged(a) =
            dbg!(parse_additional_info(&tx, ParsingContext::Event).unwrap())
        {
            if let TonEventStatus::InProcess = a {
            } else {
                panic!()
            }
        } else {
            panic!()
        };
    }

    #[test]
    fn test_notify_done() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAARAAA693Z4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCAAACgpY0FkKsGZIkbgb+dAhZwgZ18EGe+NGsuMOe6ebP1mZa9VGBSAAAAoKWNBZBYFZCYQABQIAwIBABUECMBhqAmgGHoSAgCCclq5dziqP8pJGLbMXsD/zoi5C1fOxaikRiOGCKuDP17sST2OxTOw8znrkarFBXwMMjxqG+Yjk6CZ5llzQdlgia8BAaAEALloADQl9gqkGhHr2dVFYNi6nXYctRsDgijXBYPrSLWcD60rAB2eLgF7s78hEMgoW34eVFgtVEla0Dbfa4KfKxb+BMYwjAYagAYUWGAAAAUFLAyfEMCshLQkM9gNAMA=").unwrap();

        if let TransactionAdditionalInfo::TonEventStatusChanged(a) =
            dbg!(parse_additional_info(&tx, ParsingContext::Event).unwrap())
        {
            if let TonEventStatus::Confirmed = a {
            } else {
                panic!()
            }
        } else {
            panic!()
        };
    }

    #[test]
    fn test_notify_eth_executed() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAARAAA7F3Z4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCAAACgpJyyIHVER8kq3HiJ7CLh63f0L6FNuFHClVei7uztOlIVx5IAgAAAoKR2jIBYFZB0QABQgKAMCAQAVBEBIicQJoBh6EgIAgnJ5eeKyWbIdllmQpwd9nH4qJGD/wzlQHDOWGC8QCKLnKVPlKWjgh4Ae4SGip4eNs+wh2HRqN6GU/Wffzz3PQ0+cAQGgBAC3aADXzfj3weHPfUJKipSKRpGGpGAwOVdhrobopP5lBZqZQQAdni4Be7O/IRDIKFt+HlRYLVRJWtA232uCnysW/gTGMIicQAYUWGAAAAUFJGt/BMCsg5ImeLTNAUA=").unwrap();

        if let TransactionAdditionalInfo::EthEventStatusChanged(a) =
            dbg!(parse_additional_info(&tx, ParsingContext::Event).unwrap())
        {
            if let EthereumStatusChanged::Executed = a {
            } else {
                panic!()
            }
        } else {
            panic!()
        };
    }

    #[test]
    fn test_notify_eth_in_progress() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAARIAA7N3Z4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCAAACgpEEkoHa2hZg3hyGFZxbZG8DRavBlR+G7vy+yz9PJyQrxh/W4QAAAnbUG/sCYFZBnwABRCRugDAgEAFwSEjciJxAmgGHoSAgCCcp0VD3BI01U2YOaQOUOy9/YQkmqW/wL8IERbo0LGwN/gcu+lArv8eOIZKRF0FR71vLLq0pv5ZIUL0wCcN2tZnDgBAaAEALdoANfN+PfB4c99QkqKlIpGkYakYDA5V2Guhuik/mUFmplBAB2eLgF7s78hEMgoW34eVFgtVEla0Dbfa4KfKxb+BMYwiJxABhRYYAAABQUhjxMEwKyDMiZ4tM0AQA==").unwrap();

        if let TransactionAdditionalInfo::EthEventStatusChanged(a) =
            dbg!(parse_additional_info(&tx, ParsingContext::Event).unwrap())
        {
            if let EthereumStatusChanged::InProcess = a {
            } else {
                panic!()
            }
        } else {
            panic!()
        };
    }

    #[test]
    fn test_eth_notify_done() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAAQ4AA693Z4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCAAACgpEEkoLbKTCjolcexnodkGoK58txUv9GyQgugOZ9EMrSi3GIHgAAAoKRBJKBYFZBnwABQIAwIBABMECInECaAYehICAIJycu+lArv8eOIZKRF0FR71vLLq0pv5ZIUL0wCcN2tZnDir/Oq0GrRrpS+ymd9014DHJx3FvKJnpwSicuDNwT4phgEBoAQAt2gA183498Hhz31CSoqUikaRhqRgMDlXYa6G6KT+ZQWamUEAHZ4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCInEAGFFhgAAAFBSGPExDArIMyJni0zQDA").unwrap();

        if let TransactionAdditionalInfo::EthEventStatusChanged(a) =
            dbg!(parse_additional_info(&tx, ParsingContext::Event).unwrap())
        {
            if let EthereumStatusChanged::Confirmed = a {
            } else {
                panic!()
            }
        } else {
            panic!()
        };
    }

    #[test]
    fn multisig_submit() {
        let tx = Transaction::construct_from_base64("te6ccgECDAEAAkMAA693d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3AAAEv38uN8H+CfBrFklcU0i9Vs4RZzxi5vtTa9PqJ/LpPctz/rat2wAABIjJ0UsBX2sytAADQIBQQBAgcMBgRAAwIAYcAAAAAAAAIAAAAAAAOylU78GhKKYOUuj1Rh3dLpOOzgJUEyoySchhaM60lDREBQDowAnUfXAxOIAAAAAAAAAABtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAgnJ5QDnTzA46E1KOsPz7QLrshaiw53aaaTNY7TZfFM9uf9wCstMqmz8MmfSmYLSpRuMah9ruqiOVsRPjzhTEdu9aAgHgCAYBAd8HAHXn+7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u4AAAJfv5cb4S+1mVoSY7BZq+1mVo/lxvgwAFFif7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7gwJAeGUlZeW3g4p7fOroeyZUZdj1hWrKWusR/Na6V9uRhKJvV3dgWDQ1/YR5hQfYLaM861DgLJMku/LPDKMt43TyJUH+ToLdTA3yCwRnsc9IMg9JIXlsbI92/1mZ+RrZF1GGY1AAABdLq+AHhfazLsEx2CzYAoBY4AVKmRhQN1a9YbnwdGmdH0KtPv2SINcG4FpEDjh70ON2qAAAAAAAAAAAAAdjv+NHoAUCwAA").unwrap();
        assert!(matches!(
            parse_additional_info(&tx, ParsingContext::Multisig).unwrap(),
            TransactionAdditionalInfo::MultisigSubmitTransaction(_)
        ))
    }

    #[test]
    fn multisig_confirm() {
        let tx = Transaction::construct_from_base64("te6ccgECCgEAAjAAA693d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3AAAJcbrc/8GSsRcwsaEKUmFwdbT9tmaf3vKqKpeWIR9/9GyMA8r2+gAACXGutDTBYBvSYwADQIBQQBAgcMBgRAAwIAYcAAAAAAAAIAAAAAAAI1K3sqU+I63UTJ+xkdHcyrkM2hxcBJu//z7hF+/hEtukBQFcwAnUYtYxOIAAAAAAAAAABSwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAgnITMJnhiVklA89yLWhQU+4BB1tJ3iPLRRZoWlPVKSkbvYENWnQphG03/JbEJJWwJbdhZCl+oH7UI7ARqCUcU6H/AgHgCAYBAd8HAK9J/u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7vACa4ZyAEEjOHCY7aEkcDRTMruTfdNxrg9GyWxKU18Pes2WvMQekAAAAAABLjdbn/hMA3pMZAAUWJ/u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uDAkA8c+cpxQ8FYd2C/XWiibmIX4wPfvHIultapCNOhW5dJ5hl2YD+PHO24RUXdbY669yR8BUfGNuxVTwVkV1K0HA7QByTARuQhGj9eozhRteIImtsExhdcFckfL9FqBq5uNuaoAAAF3bK3Ps2Ab0p4ap0DtYBvF9mf0BgGA=").unwrap();
        assert!(matches!(
            parse_additional_info(&tx, ParsingContext::Multisig).unwrap(),
            TransactionAdditionalInfo::MultisigConfirmTransaction(_)
        ))
    }
}
