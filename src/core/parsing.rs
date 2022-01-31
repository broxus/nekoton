use std::convert::TryFrom;

use anyhow::Result;
use num_bigint::BigUint;
use once_cell::race::OnceBox;
use ton_block::MsgAddressInt;
use ton_types::UInt256;

use nekoton_abi::*;

use crate::core::models::*;
use crate::core::ton_wallet::WalletType;

pub struct InputMessage(pub Vec<ton_abi::Token>);

pub struct ContractCall {
    pub inputs: Vec<ton_abi::Token>,
    pub outputs: Vec<ton_abi::Token>,
}

pub fn parse_payload(payload: ton_types::SliceData) -> Option<KnownPayload> {
    let function_id = read_function_id(&payload).ok()?;
    if function_id == 0 {
        return parse_comment_payload(payload).map(KnownPayload::Comment);
    }

    // TODO: somehow determine token wallet version
    let functions = TokenWalletFunctions::for_version(TokenWalletVersion::OldTip3v4)?;

    if function_id == functions.transfer.input_id {
        let inputs = functions.transfer.decode_input(payload, true).ok()?;

        TokenOutgoingTransfer::try_from((InputMessage(inputs), TransferType::ByTokenWalletAddress))
            .map(KnownPayload::TokenOutgoingTransfer)
            .ok()
    } else if function_id == functions.transfer_to_recipient.input_id {
        let inputs = functions
            .transfer_to_recipient
            .decode_input(payload, true)
            .ok()?;

        TokenOutgoingTransfer::try_from((InputMessage(inputs), TransferType::ByOwnerWalletAddress))
            .map(KnownPayload::TokenOutgoingTransfer)
            .ok()
    } else if function_id == functions.burn_by_owner.input_id {
        let inputs = functions.burn_by_owner.decode_input(payload, true).ok()?;

        TokenSwapBack::try_from(InputMessage(inputs))
            .map(KnownPayload::TokenSwapBack)
            .ok()
    } else {
        None
    }
}

pub fn parse_transaction_additional_info(
    tx: &ton_block::Transaction,
    wallet_type: WalletType,
) -> Option<TransactionAdditionalInfo> {
    let in_msg = tx.in_msg.as_ref()?.read_struct().ok()?;

    let int_header = match in_msg.header() {
        ton_block::CommonMsgInfo::ExtInMsgInfo(_) => {
            let (recipient, known_payload, method) = match wallet_type {
                WalletType::WalletV3 => {
                    let mut out_msg = None;
                    tx.out_msgs
                        .iterate(|item| {
                            out_msg = Some(item.0);
                            Ok(false)
                        })
                        .ok()?;

                    let out_msg = out_msg?;
                    let recipient = match out_msg.header() {
                        ton_block::CommonMsgInfo::IntMsgInfo(header) => &header.dst,
                        _ => return None,
                    };

                    let known_payload = out_msg.body().and_then(parse_payload);

                    (
                        Some(recipient.clone()),
                        known_payload,
                        WalletInteractionMethod::WalletV3Transfer,
                    )
                }
                WalletType::Multisig(_) => {
                    let method = parse_multisig_transaction_impl(in_msg, tx)?;
                    let (recipient, known_payload) = match &method {
                        MultisigTransaction::Submit(MultisigSubmitTransaction {
                            payload,
                            dest,
                            ..
                        })
                        | MultisigTransaction::Send(MultisigSendTransaction {
                            payload,
                            dest,
                            ..
                        }) => (Some(dest.clone()), parse_payload(payload.clone().into())),
                        MultisigTransaction::Confirm(_) => (None, None),
                    };

                    (
                        recipient,
                        known_payload,
                        WalletInteractionMethod::Multisig(Box::new(method)),
                    )
                }
            };

            return Some(TransactionAdditionalInfo::WalletInteraction(
                WalletInteractionInfo {
                    recipient,
                    known_payload,
                    method,
                },
            ));
        }
        ton_block::CommonMsgInfo::IntMsgInfo(header) => header,
        ton_block::CommonMsgInfo::ExtOutMsgInfo(_) => return None,
    };

    let depool_notifications = DePoolParticipantFunctions::instance();
    let token_notifications = WalletNotificationFunctions::instance();

    if int_header.bounced {
        return None;
    }

    let body = in_msg.body()?;
    let function_id = read_function_id(&body).ok()?;

    if function_id == 0 {
        parse_comment_payload(body).map(TransactionAdditionalInfo::Comment)
    } else if function_id == depool_notifications.on_round_complete.input_id {
        let inputs = depool_notifications
            .on_round_complete
            .decode_input(body, true)
            .ok()?;

        DePoolOnRoundCompleteNotification::try_from(InputMessage(inputs))
            .map(TransactionAdditionalInfo::DePoolOnRoundComplete)
            .ok()
    } else if function_id == depool_notifications.receive_answer.input_id {
        let inputs = depool_notifications
            .receive_answer
            .decode_input(body, true)
            .ok()?;

        DePoolReceiveAnswerNotification::try_from(InputMessage(inputs))
            .map(TransactionAdditionalInfo::DePoolReceiveAnswer)
            .ok()
    } else if function_id == token_notifications.notify_wallet_deployed.input_id {
        let inputs = token_notifications
            .notify_wallet_deployed
            .decode_input(body, true)
            .ok()?;

        TokenWalletDeployedNotification::try_from(InputMessage(inputs))
            .map(TransactionAdditionalInfo::TokenWalletDeployed)
            .ok()
    } else {
        None
    }
}

struct DePoolParticipantFunctions {
    on_round_complete: &'static ton_abi::Function,
    receive_answer: &'static ton_abi::Function,
}

impl DePoolParticipantFunctions {
    fn instance() -> &'static Self {
        use nekoton_contracts::wallets::notifications;

        static IDS: OnceBox<DePoolParticipantFunctions> = OnceBox::new();
        IDS.get_or_init(|| {
            Box::new(DePoolParticipantFunctions {
                on_round_complete: notifications::depool_on_round_complete(),
                receive_answer: notifications::depool_receive_answer(),
            })
        })
    }
}

struct WalletNotificationFunctions {
    notify_wallet_deployed: &'static ton_abi::Function,
}

impl WalletNotificationFunctions {
    fn instance() -> &'static Self {
        use nekoton_contracts::wallets::notifications;

        static IDS: OnceBox<WalletNotificationFunctions> = OnceBox::new();
        IDS.get_or_init(|| {
            Box::new(WalletNotificationFunctions {
                notify_wallet_deployed: notifications::notify_wallet_deployed(),
            })
        })
    }
}

impl TryFrom<InputMessage> for DePoolOnRoundCompleteNotification {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> Result<Self, Self::Error> {
        let input: DePoolOnRoundCompleteNotification = value.0.unpack()?;

        Ok(Self {
            round_id: input.round_id,
            reward: input.reward,
            ordinary_stake: input.ordinary_stake,
            vesting_stake: input.vesting_stake,
            lock_stake: input.lock_stake,
            reinvest: input.reinvest,
            reason: input.reason,
        })
    }
}

impl TryFrom<InputMessage> for DePoolReceiveAnswerNotification {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> Result<Self, Self::Error> {
        let input: DePoolReceiveAnswerNotification = value.0.unpack()?;

        Ok(Self {
            error_code: input.error_code,
            comment: input.comment,
        })
    }
}

impl TryFrom<InputMessage> for TokenWalletDeployedNotification {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> Result<Self, Self::Error> {
        let input: TokenWalletDeployedNotification = value.0.unpack()?;

        Ok(Self {
            root_token_contract: input.root_token_contract,
        })
    }
}

pub fn parse_multisig_transaction(tx: &ton_block::Transaction) -> Option<MultisigTransaction> {
    let in_msg = tx.in_msg.as_ref()?.read_struct().ok()?;
    if !matches!(in_msg.header(), ton_block::CommonMsgInfo::ExtInMsgInfo(_)) {
        return None;
    }
    parse_multisig_transaction_impl(in_msg, tx)
}

fn parse_multisig_transaction_impl(
    in_msg: ton_block::Message,
    tx: &ton_block::Transaction,
) -> Option<MultisigTransaction> {
    const PUBKEY_OFFSET: usize = 1 + ed25519_dalek::SIGNATURE_LENGTH * 8 + 1;
    const PUBKEY_LENGTH: usize = 256;
    const TIME_LENGTH: usize = 64;
    const EXPIRE_LENGTH: usize = 32;

    let mut body = in_msg.body()?;
    let function_id = {
        let mut body = body.clone();

        // Shift body by Maybe(signature), Maybe(pubkey), time and expire
        body.move_by(PUBKEY_OFFSET + PUBKEY_LENGTH + TIME_LENGTH + EXPIRE_LENGTH)
            .ok()?;

        read_function_id(&body).ok()?
    };

    let functions = MultisigFunctions::instance();

    if function_id == functions.send_transaction.input_id {
        let tokens = functions.send_transaction.decode_input(body, false).ok()?;

        MultisigSendTransaction::try_from(InputMessage(tokens))
            .map(MultisigTransaction::Send)
            .ok()
    } else if function_id == functions.submit_transaction.input_id {
        let inputs = functions
            .submit_transaction
            .decode_input(body.clone(), false)
            .ok()?;
        let outputs = functions.submit_transaction.parse(tx).ok()?;

        body.move_by(PUBKEY_OFFSET).ok()?;

        let custodian = body.get_next_hash().ok()?;
        MultisigSubmitTransaction::try_from((custodian, ContractCall { inputs, outputs }))
            .map(MultisigTransaction::Submit)
            .ok()
    } else if function_id == functions.confirm_transaction.input_id {
        let inputs = functions
            .confirm_transaction
            .decode_input(body.clone(), false)
            .ok()?;

        body.move_by(PUBKEY_OFFSET).ok()?;

        let custodian = body.get_next_hash().ok()?;
        MultisigConfirmTransaction::try_from((custodian, InputMessage(inputs)))
            .map(MultisigTransaction::Confirm)
            .ok()
    } else {
        None
    }
}

struct MultisigFunctions {
    send_transaction: &'static ton_abi::Function,
    submit_transaction: &'static ton_abi::Function,
    confirm_transaction: &'static ton_abi::Function,
}

impl MultisigFunctions {
    fn instance() -> &'static Self {
        use nekoton_contracts::wallets::multisig;

        static IDS: OnceBox<MultisigFunctions> = OnceBox::new();
        IDS.get_or_init(|| {
            Box::new(MultisigFunctions {
                send_transaction: multisig::send_transaction(),
                submit_transaction: multisig::submit_transaction(),
                confirm_transaction: multisig::confirm_transaction(),
            })
        })
    }
}

impl TryFrom<(UInt256, InputMessage)> for MultisigConfirmTransaction {
    type Error = UnpackerError;

    fn try_from((custodian, value): (UInt256, InputMessage)) -> Result<Self, Self::Error> {
        let output: MultisigConfirmTransaction = value.0.unpack()?;
        Ok(Self {
            custodian,
            transaction_id: output.transaction_id,
        })
    }
}

#[derive(UnpackAbiPlain)]
struct MultisigSubmitTransactionInput {
    #[abi(address)]
    dest: MsgAddressInt,
    #[abi(with = "uint128_number")]
    value: BigUint,
    #[abi(bool)]
    bounce: bool,
    #[abi(bool, name = "allBalance")]
    all_balance: bool,
    #[abi(cell)]
    payload: ton_types::Cell,
}

#[derive(UnpackAbiPlain)]
struct MultisigSubmitTransactionOutput {
    #[abi(uint64, name = "transId")]
    trans_id: u64,
}

impl TryFrom<(UInt256, ContractCall)> for MultisigSubmitTransaction {
    type Error = UnpackerError;

    fn try_from((custodian, value): (UInt256, ContractCall)) -> Result<Self, Self::Error> {
        let input: MultisigSubmitTransactionInput = value.inputs.unpack()?;
        let output: MultisigSubmitTransactionOutput = value.outputs.unpack()?;

        Ok(Self {
            custodian,
            dest: input.dest,
            value: input.value,
            bounce: input.bounce,
            all_balance: input.all_balance,
            payload: input.payload,
            trans_id: output.trans_id,
        })
    }
}

impl TryFrom<InputMessage> for MultisigSendTransaction {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> Result<Self, Self::Error> {
        let input: MultisigSendTransaction = value.0.unpack()?;

        Ok(Self {
            dest: input.dest,
            value: input.value,
            bounce: input.bounce,
            flags: input.flags,
            payload: input.payload,
        })
    }
}

pub fn parse_token_transaction(
    tx: &ton_block::Transaction,
    description: &ton_block::TransactionDescrOrdinary,
    version: TokenWalletVersion,
) -> Option<TokenWalletTransaction> {
    if description.aborted {
        return None;
    }

    let functions = TokenWalletFunctions::for_version(version)?;

    let in_msg = tx.in_msg.as_ref()?.read_struct().ok()?;

    let mut body = in_msg.body()?;
    let function_id = read_function_id(&body).ok()?;

    let header = in_msg.int_header()?;
    if header.bounced {
        body.move_by(32).ok()?;
        let function_id = read_function_id(&body).ok()?;
        body.move_by(32).ok()?;

        if function_id == functions.internal_transfer.input_id {
            return Some(TokenWalletTransaction::TransferBounced(
                body.get_next_u128().ok()?.into(),
            ));
        }

        let root_contract_functions = RootTokenContractFunctions::for_version(version)?;
        if function_id == root_contract_functions.tokens_burned.input_id {
            Some(TokenWalletTransaction::SwapBackBounced(
                body.get_next_u128().ok()?.into(),
            ))
        } else {
            None
        }
    } else if function_id == functions.accept.input_id {
        let inputs = functions.accept.decode_input(body, true).ok()?;

        Accept::try_from(InputMessage(inputs))
            .map(|Accept { tokens }| TokenWalletTransaction::Accept(tokens))
            .ok()
    } else if function_id == functions.transfer.input_id {
        let inputs = functions.transfer.decode_input(body, true).ok()?;

        TokenOutgoingTransfer::try_from((InputMessage(inputs), TransferType::ByTokenWalletAddress))
            .map(TokenWalletTransaction::OutgoingTransfer)
            .ok()
    } else if function_id == functions.transfer_to_recipient.input_id {
        let inputs = functions
            .transfer_to_recipient
            .decode_input(body, true)
            .ok()?;

        TokenOutgoingTransfer::try_from((InputMessage(inputs), TransferType::ByOwnerWalletAddress))
            .map(TokenWalletTransaction::OutgoingTransfer)
            .ok()
    } else if function_id == functions.internal_transfer.input_id {
        let inputs = functions.internal_transfer.decode_input(body, true).ok()?;

        TokenIncomingTransfer::try_from(InputMessage(inputs))
            .map(TokenWalletTransaction::IncomingTransfer)
            .ok()
    } else if function_id == functions.burn_by_owner.input_id {
        let inputs = functions.burn_by_owner.decode_input(body, true).ok()?;

        TokenSwapBack::try_from(InputMessage(inputs))
            .map(TokenWalletTransaction::SwapBack)
            .ok()
    } else {
        None
    }
}

struct TokenWalletFunctions {
    accept: &'static ton_abi::Function,
    transfer_to_recipient: &'static ton_abi::Function,
    transfer: &'static ton_abi::Function,
    internal_transfer: &'static ton_abi::Function,
    burn_by_owner: &'static ton_abi::Function,
}

impl TokenWalletFunctions {
    fn for_version(version: TokenWalletVersion) -> Option<&'static Self> {
        use nekoton_contracts::old_tip3;

        Some(match version {
            TokenWalletVersion::OldTip3v4 => {
                static IDS: OnceBox<TokenWalletFunctions> = OnceBox::new();
                IDS.get_or_init(|| {
                    Box::new(Self {
                        accept: old_tip3::token_wallet_contract::accept(),
                        transfer_to_recipient:
                            old_tip3::token_wallet_contract::transfer_to_recipient(),
                        transfer: old_tip3::token_wallet_contract::transfer(),
                        internal_transfer: old_tip3::token_wallet_contract::internal_transfer(),
                        burn_by_owner: old_tip3::token_wallet_contract::burn_by_owner(),
                    })
                })
            }
        })
    }
}

struct RootTokenContractFunctions {
    tokens_burned: &'static ton_abi::Function,
}

impl RootTokenContractFunctions {
    fn for_version(version: TokenWalletVersion) -> Option<&'static Self> {
        use nekoton_contracts::old_tip3;

        Some(match version {
            TokenWalletVersion::OldTip3v4 => {
                static IDS: OnceBox<RootTokenContractFunctions> = OnceBox::new();
                IDS.get_or_init(|| {
                    Box::new(Self {
                        tokens_burned: old_tip3::root_token_contract::tokens_burned(),
                    })
                })
            }
        })
    }
}

#[derive(UnpackAbiPlain)]
struct TonTokenWalletBurnByOwner {
    #[abi(with = "uint128_number")]
    tokens: BigUint,
    #[abi(name = "grams", with = "uint128_number")]
    _grams: BigUint,
    #[abi(address, name = "send_gas_to")]
    _send_gas_to: MsgAddressInt,
    #[abi(address, name = "callback_address")]
    callback_address: MsgAddressInt,
    #[abi(cell)]
    callback_payload: ton_types::Cell,
}

impl TryFrom<InputMessage> for TokenSwapBack {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> Result<Self, Self::Error> {
        let input: TonTokenWalletBurnByOwner = value.0.unpack()?;

        Ok(TokenSwapBack {
            tokens: input.tokens,
            callback_address: input.callback_address,
            callback_payload: input.callback_payload,
        })
    }
}

#[derive(UnpackAbiPlain)]
struct Accept {
    #[abi(with = "uint128_number")]
    tokens: BigUint,
}

impl TryFrom<InputMessage> for Accept {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> Result<Self, Self::Error> {
        let input: Accept = value.0.unpack()?;

        Ok(Accept {
            tokens: input.tokens,
        })
    }
}

enum TransferType {
    ByOwnerWalletAddress,
    ByTokenWalletAddress,
}

#[derive(UnpackAbiPlain)]
struct TonTokenWalletTransferToRecipient {
    #[abi(name = "recipient_public_key", with = "uint256_bytes")]
    _recipient_public_key: UInt256,
    #[abi(address)]
    recipient_address: MsgAddressInt,
    #[abi(with = "uint128_number")]
    tokens: BigUint,
    #[abi(name = "deploy_grams", with = "uint128_number")]
    _deploy_grams: BigUint,
    #[abi(name = "transfer_grams", with = "uint128_number")]
    _transfer_grams: BigUint,
    #[abi(address, name = "send_gas_to")]
    _send_gas_to: MsgAddressInt,
    #[abi(bool, name = "notify_receiver")]
    _notify_receiver: bool,
    #[abi(cell, name = "payload")]
    _payload: ton_types::Cell,
}

#[derive(UnpackAbiPlain)]
struct TonTokenWalletTransfer {
    #[abi(address)]
    to: MsgAddressInt,
    #[abi(with = "uint128_number")]
    tokens: BigUint,
    #[abi(name = "grams", with = "uint128_number")]
    _grams: BigUint,
    #[abi(address, name = "send_gas_to")]
    _send_gas_to: MsgAddressInt,
    #[abi(bool, name = "notify_receiver")]
    _notify_receiver: bool,
    #[abi(cell, name = "payload")]
    _payload: ton_types::Cell,
}

impl TryFrom<(InputMessage, TransferType)> for TokenOutgoingTransfer {
    type Error = UnpackerError;

    fn try_from((value, transfer_type): (InputMessage, TransferType)) -> Result<Self, Self::Error> {
        let data = match transfer_type {
            // "transferToRecipient"
            TransferType::ByOwnerWalletAddress => {
                let input: TonTokenWalletTransferToRecipient = value.0.unpack()?;
                TokenOutgoingTransfer {
                    to: TransferRecipient::OwnerWallet(input.recipient_address),
                    tokens: input.tokens,
                }
            }
            // "transfer
            TransferType::ByTokenWalletAddress => {
                let input: TonTokenWalletTransfer = value.0.unpack()?;
                TokenOutgoingTransfer {
                    to: TransferRecipient::TokenWallet(input.to),
                    tokens: input.tokens,
                }
            }
        };

        Ok(data)
    }
}

#[derive(UnpackAbiPlain)]
struct TonTokenWalletInternalTransfer {
    #[abi(with = "uint128_number")]
    tokens: BigUint,
    #[abi(name = "sender_public_key", with = "uint256_bytes")]
    _sender_public_key: UInt256,
    #[abi(address, name = "sender_address")]
    sender_address: MsgAddressInt,
    #[abi(address, name = "send_gas_to")]
    _send_gas_to: MsgAddressInt,
    #[abi(bool, name = "notify_receiver")]
    _notify_receiver: bool,
    #[abi(cell, name = "payload")]
    _payload: ton_types::Cell,
}

impl TryFrom<InputMessage> for TokenIncomingTransfer {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> Result<Self, Self::Error> {
        let input: TonTokenWalletInternalTransfer = value.0.unpack()?;

        Ok(TokenIncomingTransfer {
            tokens: input.tokens,
            sender_address: input.sender_address,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ton_block::{Deserializable, Transaction, TransactionDescrOrdinary};

    use super::*;
    use crate::core::ton_wallet::MultisigType;

    fn parse_transaction(data: &str) -> (Transaction, TransactionDescrOrdinary) {
        let tx = Transaction::construct_from_base64(data).unwrap();
        let description = match tx.description.read_struct().unwrap() {
            ton_block::TransactionDescr::Ordinary(description) => description,
            _ => panic!(),
        };
        (tx, description)
    }

    #[test]
    fn test_transaction_with_comment() {
        let tx = Transaction::construct_from_base64("te6ccgECCAEAAa0AA7V6khRTRyNmt/7uwVMjqWtdzxcZfIjcDUV436UpALijPLAAALi67rDsNGkd3DyaHde6qGSNyU7rxIrKKUFCg2XCiOWm8qj/wgcwAAC4uu6w7BYG3S5AABRh6EgIBQQBAhUECQ7msoAYYehIEQMCAFvAAAAAAAAAAAAAAAABLUUtpEnlC4z33SeGHxRhIq/htUa7i3D8ghbwxhQTn44EAJwnzD0JAAAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgnI6oOa5hnaAmb92gCQ5BlaDDjAmDoH5UvSJNuK95TfvcajtZ/eBLgOpVpjmuIPSjgFKd0RzU/MXZ1uRuop7DU5HAQGgBgG5aAFSQopo5GzW/93YKmR1LWu54uMvkRuBqK8b9KUgFxRnlwAqSFFNHI2a3/u7BUyOpa13PFxl8iNwNRXjfpSkAuKM8tDuaygABhnMOAAAFxdd1h2EwNulyAAAAABABwAqaSBsb3ZlIG1lbWVzIGFuZCDwn6aA").unwrap();

        assert!(matches!(
            parse_transaction_additional_info(&tx, WalletType::WalletV3).unwrap(),
            TransactionAdditionalInfo::Comment(_)
        ));
    }

    #[test]
    fn parse_depool_on_round_complete() {
        let tx = Transaction::construct_from_base64("te6ccgECBgEAATYAA7F6khRTRyNmt/7uwVMjqWtdzxcZfIjcDUV436UpALijPLAAAMhcEbrIEikkn05Ku83ZEENvShriMSDo3Wrh+PZVqEZZFR73UDNgAADIW3VTuCYJRG2wABQiKAMCAQALDERIQEkgAIJy0W3rZziZMBhdOhOSsj9f2V3MqUZWvD39kx9ersOjLDlIhSvIB0KaWZELIJ7zw+I+Sy9Ykv6tSJbSpB49hDcHiQEBoAQBq0gBd5fv1pbeJAd0Wp/qbrvGFKgRUCYX7z8OHfefqT2CydMAKkhRTRyNmt/7uwVMjqWtdzxcZfIjcDUV436UpALijPLEBAYduXAAABkLgdvLrMEojabABQBbRE1D9QAAAAAAAAB5AAAAAES7c48AAATFd7ZSmgAAAAAAAAAAAAAAAAAAAACCwA==").unwrap();

        assert!(matches!(
            parse_transaction_additional_info(&tx, WalletType::WalletV3).unwrap(),
            TransactionAdditionalInfo::DePoolOnRoundComplete(_)
        ))
    }

    #[test]
    fn parse_depool_receive_answer() {
        let tx = Transaction::construct_from_base64("te6ccgECBwEAAaEAA7V6khRTRyNmt/7uwVMjqWtdzxcZfIjcDUV436UpALijPLAAAMhnsD1kVwt3ZSvzdkgOgwJsxv58wEM0BQZrsemU6arhBFJ4fxjwAADIZ7A9ZBYJRjLgABRh6EgIBQQBAhUMCQ66Pp4YYehIEQMCAFvAAAAAAAAAAAAAAAABLUUtpEnlC4z33SeGHxRhIq/htUa7i3D8ghbwxhQTn44EAJwnzDxS7AAAAAAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgnIEOMO6fRXte5PGI5jiEUhiDtcNPCIWL5NWNQNOK9Xcl+MnFzrWwqjP3BjSUMj+iqVsHR/XXRK4EG15vN19dQTxAQGgBgDRSAFA+IzRUVgwA2vU75DcYvlAT67YURjbSaU6+j+uLV/oFQAqSFFNHI2a3/u7BUyOpa13PFxl8iNwNRXjfpSkAuKM8tDro+ngBhRYYAAAGQz2B6yIwSjGXB+ITyIAAAADAAAAAAAAAABA").unwrap();

        assert!(matches!(
            parse_transaction_additional_info(&tx, WalletType::WalletV3).unwrap(),
            TransactionAdditionalInfo::DePoolReceiveAnswer(_)
        ))
    }

    #[test]
    fn test_parse_wallet_deployment() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAATAAA7F44lhmAlE+maVfor4IVhRpx85Rp9WiWXdVjnfvK8k4e0AAALc5peDsFNAtcF1BRBGfRP73+ljNPUUc+ir7FmHntIcbeh/ba28gAAC3OZS2ZBYGofQAABQgSAMCAQAVBECIicQJoBh6EgIAgnIIhWuBGHA/f3IsyBPHr57C3d7pcU83NmIoz5CkFu+Hsn742ILtpOsOCyUw6fEN9VwMZzJ8dj6MuR/kKlztR9sKAQGgBAD3aAHILrQNhiymjQB0/Pw/ubdxFv4FXRIQhcVcOMZMH8eJ5wAjiWGYCUT6ZpV+ivghWFGnHzlGn1aJZd1WOd+8ryTh7QicQAYUWGAAABbnNEILiMDUPm4kKd2bwA7tPzMWNNSaXaK1RvRlLdSIlIehh8LvndIgPP8XtYTj2A==").unwrap();

        assert!(matches!(
            parse_transaction_additional_info(&tx, WalletType::WalletV3).unwrap(),
            TransactionAdditionalInfo::TokenWalletDeployed(_)
        ));
    }

    #[test]
    fn test_parse_wallet_v3_transfer() {
        let tx = Transaction::construct_from_base64("te6ccgECCgEAAkgAA7V6khRTRyNmt/7uwVMjqWtdzxcZfIjcDUV436UpALijPLAAAOsYeZvcH4TzG78Qm4432VnPT2nEy4Ms4gzZ+kR9Dc3m2ovCml6wAADqzLEDICYOmNuQADRpPeiIBQQBAhEMggEGGW16hEADAgBvyYehIEwUWEAAAAAAAAIAAAAAAAPgixOHXZ98UI4dij2WkyFV1pxMvMnheV/eiEMi5McOJkBQFgwAnUF2QxOIAAAAAAAAAAAQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAgnKb5t2GaSGpykknfbY8sbLCoUmDjRnHY8ac6h6aQu56Ln3v5XCybUkA/gfrXRR3FEMh6/ByWbJu6d1D4Gxa7IrOAgHgCAYBAd8HALFIAVJCimjkbNb/3dgqZHUta7ni4y+RG4Gorxv0pSAXFGeXACpIUU0cjZrf+7sFTI6lrXc8XGXyI3A1FeN+lKQC4ozy0O5rKAAGFFhgAAAdYw8ze4TB0xtyQAHfiAFSQopo5GzW/93YKmR1LWu54uMvkRuBqK8b9KUgFxRnlgOVFdAK7dI4eTxuEFTOhLxRr9wbXDgGzg0hdU9yZ5Fh4kK1kUZwoNhGrMoZQuRfhZC579ikC131c9r3A1GPZdA6XUlsUwdMb1gAABcAHAkAaEIAVJCimjkbNb/3dgqZHUta7ni4y+RG4Gorxv0pSAXFGeWh3NZQAAAAAAAAAAAAAAAAAAA=").unwrap();

        assert!(matches!(
            parse_transaction_additional_info(&tx, WalletType::WalletV3).unwrap(),
            TransactionAdditionalInfo::WalletInteraction(WalletInteractionInfo {
                recipient: Some(_),
                known_payload: None,
                method: WalletInteractionMethod::WalletV3Transfer,
            })
        ))
    }

    #[test]
    fn test_parse_multisig_submit() {
        let tx = Transaction::construct_from_base64("te6ccgECDAEAAkMAA693d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3AAAEv38uN8H+CfBrFklcU0i9Vs4RZzxi5vtTa9PqJ/LpPctz/rat2wAABIjJ0UsBX2sytAADQIBQQBAgcMBgRAAwIAYcAAAAAAAAIAAAAAAAOylU78GhKKYOUuj1Rh3dLpOOzgJUEyoySchhaM60lDREBQDowAnUfXAxOIAAAAAAAAAABtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAgnJ5QDnTzA46E1KOsPz7QLrshaiw53aaaTNY7TZfFM9uf9wCstMqmz8MmfSmYLSpRuMah9ruqiOVsRPjzhTEdu9aAgHgCAYBAd8HAHXn+7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u4AAAJfv5cb4S+1mVoSY7BZq+1mVo/lxvgwAFFif7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7gwJAeGUlZeW3g4p7fOroeyZUZdj1hWrKWusR/Na6V9uRhKJvV3dgWDQ1/YR5hQfYLaM861DgLJMku/LPDKMt43TyJUH+ToLdTA3yCwRnsc9IMg9JIXlsbI92/1mZ+RrZF1GGY1AAABdLq+AHhfazLsEx2CzYAoBY4AVKmRhQN1a9YbnwdGmdH0KtPv2SINcG4FpEDjh70ON2qAAAAAAAAAAAAAdjv+NHoAUCwAA").unwrap();

        let custodian =
            UInt256::from_str("e4e82dd4c0df20b0467b1cf48320f4921796c6c8f76ff5999f91ad9175186635")
                .unwrap();

        assert!(matches!(
            parse_transaction_additional_info(
                &tx,
                WalletType::Multisig(MultisigType::SafeMultisigWallet)
            )
            .unwrap(),
            TransactionAdditionalInfo::WalletInteraction(WalletInteractionInfo {
                recipient: Some(_),
                known_payload: None,
                method: WalletInteractionMethod::Multisig(data)
            }) if matches!(&*data, MultisigTransaction::Submit(submit) if submit.custodian == custodian)
        ));
    }

    #[test]
    fn test_parse_multisig_confirm() {
        let tx = Transaction::construct_from_base64("te6ccgECCgEAAjAAA693d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3AAAJcbrc/8GSsRcwsaEKUmFwdbT9tmaf3vKqKpeWIR9/9GyMA8r2+gAACXGutDTBYBvSYwADQIBQQBAgcMBgRAAwIAYcAAAAAAAAIAAAAAAAI1K3sqU+I63UTJ+xkdHcyrkM2hxcBJu//z7hF+/hEtukBQFcwAnUYtYxOIAAAAAAAAAABSwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAgnITMJnhiVklA89yLWhQU+4BB1tJ3iPLRRZoWlPVKSkbvYENWnQphG03/JbEJJWwJbdhZCl+oH7UI7ARqCUcU6H/AgHgCAYBAd8HAK9J/u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7vACa4ZyAEEjOHCY7aEkcDRTMruTfdNxrg9GyWxKU18Pes2WvMQekAAAAAABLjdbn/hMA3pMZAAUWJ/u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uDAkA8c+cpxQ8FYd2C/XWiibmIX4wPfvHIultapCNOhW5dJ5hl2YD+PHO24RUXdbY669yR8BUfGNuxVTwVkV1K0HA7QByTARuQhGj9eozhRteIImtsExhdcFckfL9FqBq5uNuaoAAAF3bK3Ps2Ab0p4ap0DtYBvF9mf0BgGA=").unwrap();

        let custodian =
            UInt256::from_str("c93011b908468fd7a8ce146d788226b6c13185d7057247cbf45a81ab9b8db9aa")
                .unwrap();

        assert!(matches!(
            parse_transaction_additional_info(
                &tx,
                WalletType::Multisig(MultisigType::SafeMultisigWallet)
            )
            .unwrap(),
            TransactionAdditionalInfo::WalletInteraction(WalletInteractionInfo {
                recipient: None,
                known_payload: None,
                method: WalletInteractionMethod::Multisig(data)
            }) if matches!(&*data, MultisigTransaction::Confirm(confirm) if confirm.custodian == custodian)
        ))
    }

    #[test]
    fn test_parse_bounced_tokens_transfer() {
        let (tx, description) = parse_transaction("te6ccgECCQEAAiEAA7V9jKvgMYxeLukedeW/PRr7QyRzEpkal33nb9KfgpelA3AAAO1mmxCMEy4UbEGiIQKVpE2nzO2Ar32k7H36ni1NMpxrcPorUNuwAADtZo+e3BYO9BHwADRwGMkIBQQBAhcMSgkCmI36GG92AhEDAgBvyYehIEwUWEAAAAAAAAQAAgAAAAKLF5Ge7DorMQ9dbEzZTgWK7Jiugap8s4dRpkiQl7CNEEBQFgwAnkP1TAqiBAAAAAAAAAAAtgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgnIBZa/nTbAD2Vcr8A6p+uT7XD4tLowmBLZEuIHLxU1zbeHGgHFi5dfeWnrNgtL3FHE6zw6ysjTJJI3LFFDAgPi3AgHgCAYBAd8HALFoAbGVfAYxi8XdI868t+ejX2hkjmJTI1LvvO36U/BS9KBvABgzjiRJUfoXsV99CuD/WnKK4QN5mlferMiVbk0Y3Jc3ECddFmAGFFhgAAAdrNNiEYTB3oI+QAD5WAHF6/YBDYNj7TABzedO3/4+ENpaE0PhwRx5NFYisFNfpQA2Mq+AxjF4u6R515b89GvtDJHMSmRqXfedv0p+Cl6UDdApiN+gBhRYYAAAHazSjHIEwd6CFH////+MaQuBAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAEA=");

        assert!(matches!(
            parse_token_transaction(&tx, &description, TokenWalletVersion::OldTip3v4).unwrap(),
            TokenWalletTransaction::TransferBounced(_)
        ));
    }
}
