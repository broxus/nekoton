use std::convert::TryFrom;

use anyhow::Result;

use ton_abi::{Token, TokenValue, Uint};
use ton_block::MsgAddress;

use ton_types::Cell;

use num_traits::ToPrimitive;

#[derive(Copy, Clone, Debug)]
pub enum ParsingContext {
    MainWallet,
    TokenWallet,
    Event,
}

///Transactions from bridge
#[derive(Clone, Debug, PartialEq)]
pub enum TransactionAdditionalInfo {
    RegularTransaction,
    //None
    //From internal input message
    // Events
    TokenWalletDeployed(MsgAddress),
    //
    EthEventStatusChanged(EthereumStatusChanged),
    //
    TonEventStatusChanged(TonEventStatus), //

    // Token transaction
    TokenTransfer(TransferFamily),
    ///Incoming
    TokenSwapBack(TokenSwapBack),
    //
    TokenMint(Mint),
    //
    TokensBounced(BounceCallback), //

    // DePool transaction
    DePoolOrdinaryStakeTransaction,
    //
    DePoolOnRoundCompleteTransaction, //

    // Multisig transaction
    MultisigDeploymentTransaction,
    //
    MultisigSubmitTransaction,
    //
    MultisigConfirmTransaction,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EthereumStatusChanged {
    InProcess = 0,
    Confirmed = 1,
    Executed = 2,
    Rejected = 3,
}

impl TryFrom<Vec<Token>> for EthereumStatusChanged {
    type Error = ();

    fn try_from(mut value: Vec<Token>) -> Result<Self, Self::Error> {
        if value.len() != 1 {
            return Err(());
        }
        let ethereum_status_changed = value.remove(0).value;

        let ethereum_status_changed = match ethereum_status_changed {
            TokenValue::Uint(a) => a.number.to_u8().ok_or(())?,
            _ => return Err(()),
        };
        let ethereum_status_changed = match ethereum_status_changed {
            0 => EthereumStatusChanged::InProcess,
            1 => EthereumStatusChanged::Confirmed,
            2 => EthereumStatusChanged::Executed,
            3 => EthereumStatusChanged::Rejected,
            _ => return Err(()),
        };

        Ok(ethereum_status_changed)
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TonEventStatus {
    InProcess = 0,
    Confirmed = 1,
    Rejected = 2,
}

impl TryFrom<Vec<Token>> for TonEventStatus {
    type Error = ();

    fn try_from(mut value: Vec<Token>) -> Result<Self, Self::Error> {
        if value.len() != 1 {
            return Err(());
        }
        let ton_event_status = value.remove(0).value;

        let ton_event_status = match ton_event_status {
            TokenValue::Uint(a) => a.number.to_u8().ok_or(())?,
            _ => return Err(()),
        };
        let ton_event_status = match ton_event_status {
            0 => TonEventStatus::InProcess,
            1 => TonEventStatus::Confirmed,
            2 => TonEventStatus::Rejected,
            _ => return Err(()),
        };

        Ok(ton_event_status)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TokenSwapBack {
    pub tokens: Uint,
    pub grams: Uint,
    pub send_gas_to: MsgAddress,
    pub callback_address: MsgAddress,
    pub callback_payload: Cell,
}

impl TryFrom<Vec<Token>> for TokenSwapBack {
    type Error = ();

    fn try_from(mut value: Vec<Token>) -> Result<Self, Self::Error> {
        if value.len() != 5 {
            return Err(());
        }
        let tokens = value.remove(0).value;
        let grams = value.remove(0).value;
        let send_gas_to = value.remove(0).value;
        let callback_address = value.remove(0).value;
        let callback_payload = value.remove(0).value;
        let tokens = match tokens {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };
        let grams = match grams {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };
        let send_gas_to = match send_gas_to {
            TokenValue::Address(a) => a,
            _ => return Err(()),
        };
        let callback_address = match callback_address {
            TokenValue::Address(a) => a,
            _ => return Err(()),
        };
        let callback_payload = match callback_payload {
            TokenValue::Cell(a) => a,
            _ => return Err(()),
        };

        Ok(TokenSwapBack {
            tokens,
            grams,
            send_gas_to,
            callback_address,
            callback_payload,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Mint {
    pub tokens: Uint,
}

impl TryFrom<Vec<Token>> for Mint {
    type Error = ();

    fn try_from(mut value: Vec<Token>) -> Result<Self, Self::Error> {
        if value.len() != 1 {
            return Err(());
        }
        let tokens = value.remove(0).value;

        let tokens = match tokens {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };
        Ok(Mint { tokens })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BounceCallback {
    pub token_wallet: MsgAddress,
    pub token_root: MsgAddress,
    pub ammount: Uint,
    pub bounced_from: MsgAddress,
    pub updated_balance: Uint,
}

impl TryFrom<Vec<Token>> for BounceCallback {
    type Error = ();

    fn try_from(mut value: Vec<Token>) -> Result<Self, Self::Error> {
        if value.len() != 5 {
            return Err(());
        }
        let token_wallet = value.remove(0).value;
        let token_root = value.remove(0).value;
        let ammount = value.remove(0).value;
        let bounced_from = value.remove(0).value;
        let updated_balance = value.remove(0).value;

        let token_wallet = match token_wallet {
            TokenValue::Address(a) => a,
            _ => return Err(()),
        };
        let token_root = match token_root {
            TokenValue::Address(a) => a,
            _ => return Err(()),
        };
        let ammount = match ammount {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };
        let bounced_from = match bounced_from {
            TokenValue::Address(a) => a,
            _ => return Err(()),
        };
        let updated_balance = match updated_balance {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };
        Ok(BounceCallback {
            token_wallet,
            token_root,
            ammount,
            bounced_from,
            updated_balance,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TransferFamily {
    Transfer(Transfer),
    TransferFrom(TransferFrom),
    TransferToRecipient(TransferToRecipient),
    InternalTransferFrom(InternalTransferFrom),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Transfer {
    pub to: MsgAddress,
    pub tokens: Uint,
    pub grams: Uint,
}

impl TryFrom<Vec<Token>> for Transfer {
    type Error = ();

    fn try_from(mut value: Vec<Token>) -> Result<Self, Self::Error> {
        let to = value.remove(0).value;
        let tokens = value.remove(0).value;
        let grams = value.remove(0).value;

        let to = match to {
            TokenValue::Address(a) => a,
            _ => return Err(()),
        };
        let tokens = match tokens {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };
        let grams = match grams {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };

        Ok(Transfer { to, tokens, grams })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransferFrom {
    pub from: MsgAddress,
    pub to: MsgAddress,
    pub tokens: Uint,
    pub grams: Uint,
}

impl TryFrom<Vec<Token>> for TransferFrom {
    type Error = ();

    fn try_from(mut value: Vec<Token>) -> Result<Self, Self::Error> {
        let from = value.remove(0).value;
        let to = value.remove(0).value;
        let tokens = value.remove(0).value;
        let grams = value.remove(0).value;

        let from = match from {
            TokenValue::Address(a) => a,
            _ => return Err(()),
        };
        let to = match to {
            TokenValue::Address(a) => a,
            _ => return Err(()),
        };
        let tokens = match tokens {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };
        let grams = match grams {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };

        Ok(TransferFrom {
            from,
            to,
            tokens,
            grams,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransferToRecipient {
    pub recipient_public_key: Uint,
    pub recipient_address: MsgAddress,
    pub tokens: Uint,
    pub transfer_grams: Uint,
}

impl TryFrom<Vec<Token>> for TransferToRecipient {
    type Error = ();

    fn try_from(mut value: Vec<Token>) -> Result<Self, Self::Error> {
        let recipient_public_key = value.remove(0).value;
        let recipient_address = value.remove(0).value;
        let tokens = value.remove(0).value;
        value.remove(0);
        let transfer_grams = value.remove(0).value;

        let recipient_public_key = match recipient_public_key {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };
        let recipient_address = match recipient_address {
            TokenValue::Address(a) => a,
            _ => return Err(()),
        };
        let tokens = match tokens {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };
        let transfer_grams = match transfer_grams {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };

        Ok(TransferToRecipient {
            recipient_public_key,
            recipient_address,
            tokens,
            transfer_grams,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct InternalTransfer {
    pub tokens: Uint,
    pub sender_public_key: Uint,
    pub sender_address: MsgAddress,
}

impl TryFrom<Vec<Token>> for InternalTransfer {
    type Error = ();

    fn try_from(mut value: Vec<Token>) -> Result<Self, Self::Error> {
        let tokens = value.remove(0).value;
        let sender_public_key = value.remove(0).value;
        let sender_address = value.remove(0).value;

        let tokens = match tokens {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };
        let sender_public_key = match sender_public_key {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };
        let sender_address = match sender_address {
            TokenValue::Address(a) => a,
            _ => return Err(()),
        };

        Ok(InternalTransfer {
            tokens,
            sender_public_key,
            sender_address,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct InternalTransferFrom {
    pub to: MsgAddress,
    pub tokens: Uint,
}

impl TryFrom<Vec<Token>> for InternalTransferFrom {
    type Error = ();

    fn try_from(mut value: Vec<Token>) -> Result<Self, Self::Error> {
        let to = value.remove(0).value;
        let tokens = value.remove(0).value;

        let to = match to {
            TokenValue::Address(a) => a,
            _ => return Err(()),
        };
        let tokens = match tokens {
            TokenValue::Uint(a) => a,
            _ => return Err(()),
        };

        Ok(InternalTransferFrom { tokens, to })
    }
}
