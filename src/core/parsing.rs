use std::convert::TryFrom;

use anyhow::Result;
use num_bigint::BigUint;
use once_cell::sync::OnceCell;
use ton_block::{MsgAddressInt, Serializable};
use ton_types::UInt256;

use nekoton_derive::UnpackAbi;

use crate::contracts;
use crate::core::models::*;
use crate::core::ton_wallet::WalletType;
use crate::helpers::abi::{self, FunctionExt, UnpackToken, UnpackerError};
use crate::utils::*;

pub struct InputMessage(pub Vec<ton_abi::Token>);

pub struct ContractCall {
    pub inputs: Vec<ton_abi::Token>,
    pub outputs: Vec<ton_abi::Token>,
}

pub fn parse_payload(payload: ton_types::SliceData) -> Option<KnownPayload> {
    let function_id = read_u32(&payload).ok()?;
    if function_id == 0 {
        return abi::parse_comment_payload(payload).map(KnownPayload::Comment);
    }

    // TODO: somehow determine token wallet version
    let functions = TokenWalletFunctions::for_version(TokenWalletVersion::Tip3v4)?;

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
    let function_id = read_u32(&body).ok()?;

    if function_id == 0 {
        abi::parse_comment_payload(body).map(TransactionAdditionalInfo::Comment)
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
    } else if function_id
        == token_notifications
            .notify_ethereum_event_status_changed
            .input_id
    {
        let inputs = token_notifications
            .notify_ethereum_event_status_changed
            .decode_input(body, true)
            .ok()?;

        EthEventStatusChanged::try_from(InputMessage(inputs))
            .map(|event| TransactionAdditionalInfo::EthEventStatusChanged(event.new_status))
            .ok()
    } else if function_id == token_notifications.notify_ton_event_status_changed.input_id {
        let inputs = token_notifications
            .notify_ton_event_status_changed
            .decode_input(body, true)
            .ok()?;

        TonEventStatusChanged::try_from(InputMessage(inputs))
            .map(|event| TransactionAdditionalInfo::TonEventStatusChanged(event.new_status))
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
    fn new(contract: &'static ton_abi::Contract) -> Self {
        Self {
            on_round_complete: contract.function("onRoundComplete").trust_me(),
            receive_answer: contract.function("receiveAnswer").trust_me(),
        }
    }

    fn instance() -> &'static Self {
        static IDS: OnceCell<DePoolParticipantFunctions> = OnceCell::new();
        IDS.get_or_init(|| DePoolParticipantFunctions::new(contracts::abi::depool_v3_participant()))
    }
}

struct WalletNotificationFunctions {
    notify_wallet_deployed: &'static ton_abi::Function,
    notify_ethereum_event_status_changed: &'static ton_abi::Function,
    notify_ton_event_status_changed: &'static ton_abi::Function,
}

impl WalletNotificationFunctions {
    fn new(contract: &'static ton_abi::Contract) -> Self {
        Self {
            notify_wallet_deployed: contract.function("notifyWalletDeployed").trust_me(),
            notify_ethereum_event_status_changed: contract
                .function("notifyEthereumEventStatusChanged")
                .trust_me(),
            notify_ton_event_status_changed: contract
                .function("notifyTonEventStatusChanged")
                .trust_me(),
        }
    }

    fn instance() -> &'static Self {
        static IDS: OnceCell<WalletNotificationFunctions> = OnceCell::new();
        IDS.get_or_init(|| WalletNotificationFunctions::new(contracts::abi::wallet_notifications()))
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

#[derive(UnpackAbi)]
#[abi(plain)]
struct EthEventStatusChanged {
    #[abi(name = "status")]
    new_status: EthEventStatus,
}

impl TryFrom<InputMessage> for EthEventStatusChanged {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> Result<Self, Self::Error> {
        let input: EthEventStatusChanged = value.0.unpack()?;

        Ok(Self {
            new_status: input.new_status,
        })
    }
}

#[derive(UnpackAbi)]
#[abi(plain)]
struct TonEventStatusChanged {
    #[abi(name = "status")]
    new_status: TonEventStatus,
}

impl TryFrom<InputMessage> for TonEventStatusChanged {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> Result<Self, Self::Error> {
        let input: TonEventStatusChanged = value.0.unpack()?;

        Ok(Self {
            new_status: input.new_status,
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

        read_u32(&body).ok()?
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
    fn new(contract: &'static ton_abi::Contract) -> Self {
        Self {
            send_transaction: contract.function("sendTransaction").trust_me(),
            submit_transaction: contract.function("submitTransaction").trust_me(),
            confirm_transaction: contract.function("confirmTransaction").trust_me(),
        }
    }

    fn instance() -> &'static Self {
        static IDS: OnceCell<MultisigFunctions> = OnceCell::new();
        IDS.get_or_init(|| MultisigFunctions::new(contracts::abi::safe_multisig_wallet()))
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

#[derive(UnpackAbi)]
#[abi(plain)]
struct MultisigSubmitTransactionInput {
    #[abi(address)]
    dest: MsgAddressInt,
    #[abi(biguint128)]
    value: BigUint,
    #[abi(bool)]
    bounce: bool,
    #[abi(bool, name = "allBalance")]
    all_balance: bool,
    #[abi(cell)]
    payload: ton_types::Cell,
}

#[derive(UnpackAbi)]
#[abi(plain)]
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
    let function_id = read_u32(&body).ok()?;

    let header = in_msg.int_header()?;
    if header.bounced {
        body.move_by(32).ok()?;
        let function_id = read_u32(&body).ok()?;

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
    fn new(contract: &'static ton_abi::Contract) -> Self {
        Self {
            accept: contract.function("accept").trust_me(),
            transfer_to_recipient: contract.function("transferToRecipient").trust_me(),
            transfer: contract.function("transfer").trust_me(),
            internal_transfer: contract.function("internalTransfer").trust_me(),
            burn_by_owner: contract.function("burnByOwner").trust_me(),
        }
    }

    fn for_version(version: TokenWalletVersion) -> Option<&'static Self> {
        Some(match version {
            TokenWalletVersion::Tip3v1 => return None,
            TokenWalletVersion::Tip3v2 => {
                static IDS: OnceCell<TokenWalletFunctions> = OnceCell::new();
                IDS.get_or_init(|| Self::new(contracts::abi::ton_token_wallet_v2()))
            }
            TokenWalletVersion::Tip3v3 => {
                static IDS: OnceCell<TokenWalletFunctions> = OnceCell::new();
                IDS.get_or_init(|| Self::new(contracts::abi::ton_token_wallet_v3()))
            }
            TokenWalletVersion::Tip3v4 => {
                static IDS: OnceCell<TokenWalletFunctions> = OnceCell::new();
                IDS.get_or_init(|| Self::new(contracts::abi::ton_token_wallet_v4()))
            }
        })
    }
}

struct RootTokenContractFunctions {
    tokens_burned: &'static ton_abi::Function,
}

impl RootTokenContractFunctions {
    fn new(contract: &'static ton_abi::Contract) -> Self {
        Self {
            tokens_burned: contract.function("tokensBurned").trust_me(),
        }
    }

    fn for_version(version: TokenWalletVersion) -> Option<&'static Self> {
        Some(match version {
            TokenWalletVersion::Tip3v1 => return None,
            TokenWalletVersion::Tip3v2 => {
                static IDS: OnceCell<RootTokenContractFunctions> = OnceCell::new();
                IDS.get_or_init(|| Self::new(contracts::abi::root_token_contract_v2()))
            }
            TokenWalletVersion::Tip3v3 => {
                static IDS: OnceCell<RootTokenContractFunctions> = OnceCell::new();
                IDS.get_or_init(|| Self::new(contracts::abi::root_token_contract_v3()))
            }
            TokenWalletVersion::Tip3v4 => {
                static IDS: OnceCell<RootTokenContractFunctions> = OnceCell::new();
                IDS.get_or_init(|| Self::new(contracts::abi::root_token_contract_v4()))
            }
        })
    }
}

#[derive(UnpackAbi)]
#[abi(plain)]
struct TonTokenWalletBurnByOwner {
    #[abi(biguint128)]
    tokens: BigUint,
    #[abi(biguint128, name = "grams")]
    _grams: BigUint,
    #[abi(address, name = "send_gas_to")]
    _send_gas_to: MsgAddressInt,
    #[abi(address, name = "callback_address")]
    _callback_address: MsgAddressInt,
    #[abi(cell)]
    callback_payload: ton_types::Cell,
}

impl TryFrom<InputMessage> for TokenSwapBack {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> Result<Self, Self::Error> {
        let input: TonTokenWalletBurnByOwner = value.0.unpack()?;

        let to = match ton_abi::TokenValue::read_from(
            &ton_abi::ParamType::Bytes,
            input
                .callback_payload
                .write_to_new_cell()
                .map_err(|_| UnpackerError::InvalidAbi)?
                .into(),
            true,
            2,
        ) {
            Ok((ton_abi::TokenValue::Bytes(destination), _)) if destination.len() == 20 => {
                format!("0x{}", hex::encode(&destination))
            }
            _ => return Err(UnpackerError::InvalidAbi),
        };

        Ok(TokenSwapBack {
            tokens: input.tokens,
            to,
        })
    }
}

#[derive(UnpackAbi)]
#[abi(plain)]
struct Accept {
    #[abi(biguint128)]
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

#[derive(UnpackAbi)]
#[abi(plain)]
struct TonTokenWalletTransferToRecipient {
    #[abi(uint256, name = "recipient_public_key")]
    _recipient_public_key: UInt256,
    #[abi(address)]
    recipient_address: MsgAddressInt,
    #[abi(biguint128)]
    tokens: BigUint,
    #[abi(biguint128, name = "deploy_grams")]
    _deploy_grams: BigUint,
    #[abi(biguint128, name = "transfer_grams")]
    _transfer_grams: BigUint,
    #[abi(address, name = "send_gas_to")]
    _send_gas_to: MsgAddressInt,
    #[abi(bool, name = "notify_receiver")]
    _notify_receiver: bool,
    #[abi(cell, name = "payload")]
    _payload: ton_types::Cell,
}

#[derive(UnpackAbi)]
#[abi(plain)]
struct TonTokenWalletTransfer {
    #[abi(address)]
    to: MsgAddressInt,
    #[abi(biguint128)]
    tokens: BigUint,
    #[abi(biguint128, name = "grams")]
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

#[derive(UnpackAbi)]
#[abi(plain)]
struct TonTokenWalletInternalTransfer {
    #[abi(biguint128)]
    tokens: BigUint,
    #[abi(uint256, name = "sender_public_key")]
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
    fn test_parse_notify_ton_event_in_progress() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAARIAA7F3Z4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCAAACgpY0FkF0icFNiz9eyMoHQj/XjOgvfd/Ty/FCTLIWVObMZeWYygAAAoKVP/JBYFZCYQABQgSAMCAQAXBECIwGGoCaAYehICAIJyfS8JL8YlmU0DmZFQVw8vxQ/7HiHzKY43/AS+wp7M2ylauXc4qj/KSRi2zF7A/86IuQtXzsWopEYjhgirgz9e7AEBoAQAuWgANCX2CqQaEevZ1UVg2Lqddhy1GwOCKNcFg+tItZwPrSsAHZ4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCMBhqABhRYYAAABQUsDJ8EwKyEtCQz2A0AQA==").unwrap();

        assert!(matches!(
            parse_transaction_additional_info(&tx, WalletType::WalletV3).unwrap(),
            TransactionAdditionalInfo::TonEventStatusChanged(TonEventStatus::InProcess)
        ));
    }

    #[test]
    fn test_parse_notify_ton_event_confirmed() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAARAAA693Z4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCAAACgpY0FkKsGZIkbgb+dAhZwgZ18EGe+NGsuMOe6ebP1mZa9VGBSAAAAoKWNBZBYFZCYQABQIAwIBABUECMBhqAmgGHoSAgCCclq5dziqP8pJGLbMXsD/zoi5C1fOxaikRiOGCKuDP17sST2OxTOw8znrkarFBXwMMjxqG+Yjk6CZ5llzQdlgia8BAaAEALloADQl9gqkGhHr2dVFYNi6nXYctRsDgijXBYPrSLWcD60rAB2eLgF7s78hEMgoW34eVFgtVEla0Dbfa4KfKxb+BMYwjAYagAYUWGAAAAUFLAyfEMCshLQkM9gNAMA=").unwrap();

        assert!(matches!(
            parse_transaction_additional_info(&tx, WalletType::WalletV3).unwrap(),
            TransactionAdditionalInfo::TonEventStatusChanged(TonEventStatus::Confirmed)
        ));
    }

    #[test]
    fn test_parse_notify_eth_event_executed() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAARAAA7F3Z4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCAAACgpJyyIHVER8kq3HiJ7CLh63f0L6FNuFHClVei7uztOlIVx5IAgAAAoKR2jIBYFZB0QABQgKAMCAQAVBEBIicQJoBh6EgIAgnJ5eeKyWbIdllmQpwd9nH4qJGD/wzlQHDOWGC8QCKLnKVPlKWjgh4Ae4SGip4eNs+wh2HRqN6GU/Wffzz3PQ0+cAQGgBAC3aADXzfj3weHPfUJKipSKRpGGpGAwOVdhrobopP5lBZqZQQAdni4Be7O/IRDIKFt+HlRYLVRJWtA232uCnysW/gTGMIicQAYUWGAAAAUFJGt/BMCsg5ImeLTNAUA=").unwrap();

        assert!(matches!(
            parse_transaction_additional_info(&tx, WalletType::WalletV3).unwrap(),
            TransactionAdditionalInfo::EthEventStatusChanged(EthEventStatus::Executed)
        ));
    }

    #[test]
    fn test_parse_notify_eth_event_in_progress() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAARIAA7N3Z4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCAAACgpEEkoHa2hZg3hyGFZxbZG8DRavBlR+G7vy+yz9PJyQrxh/W4QAAAnbUG/sCYFZBnwABRCRugDAgEAFwSEjciJxAmgGHoSAgCCcp0VD3BI01U2YOaQOUOy9/YQkmqW/wL8IERbo0LGwN/gcu+lArv8eOIZKRF0FR71vLLq0pv5ZIUL0wCcN2tZnDgBAaAEALdoANfN+PfB4c99QkqKlIpGkYakYDA5V2Guhuik/mUFmplBAB2eLgF7s78hEMgoW34eVFgtVEla0Dbfa4KfKxb+BMYwiJxABhRYYAAABQUhjxMEwKyDMiZ4tM0AQA==").unwrap();

        assert!(matches!(
            parse_transaction_additional_info(&tx, WalletType::WalletV3).unwrap(),
            TransactionAdditionalInfo::EthEventStatusChanged(EthEventStatus::InProcess)
        ));
    }

    #[test]
    fn test_parse_notify_eth_event_confirmed() {
        let tx = Transaction::construct_from_base64("te6ccgECBQEAAQ4AA693Z4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCAAACgpEEkoLbKTCjolcexnodkGoK58txUv9GyQgugOZ9EMrSi3GIHgAAAoKRBJKBYFZBnwABQIAwIBABMECInECaAYehICAIJycu+lArv8eOIZKRF0FR71vLLq0pv5ZIUL0wCcN2tZnDir/Oq0GrRrpS+ymd9014DHJx3FvKJnpwSicuDNwT4phgEBoAQAt2gA183498Hhz31CSoqUikaRhqRgMDlXYa6G6KT+ZQWamUEAHZ4uAXuzvyEQyChbfh5UWC1USVrQNt9rgp8rFv4ExjCInEAGFFhgAAAFBSGPExDArIMyJni0zQDA").unwrap();

        assert!(matches!(
            parse_transaction_additional_info(&tx, WalletType::WalletV3).unwrap(),
            TransactionAdditionalInfo::EthEventStatusChanged(EthEventStatus::Confirmed)
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
    fn test_parse_transfer_to_wallet_owner() {
        let (tx, description) = parse_transaction("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");

        assert!(matches!(
            parse_token_transaction(&tx, &description, TokenWalletVersion::Tip3v3).unwrap(),
            TokenWalletTransaction::OutgoingTransfer(a) if matches!(a.to, TransferRecipient::OwnerWallet(_))
        ));
    }

    #[test]
    fn test_parse_transfer_to_token_wallet() {
        let (tx, description) = parse_transaction("te6ccgECDAEAAugAA7d/AxqO0U7QTnYewCYNWriQfk3gBkNp5RAP5xRZRXYCQlAAALt1acOwEwTSfvN485NtXi/d5fLduHfHgoEjmIjVnX44+VcVmdrgAAC3oGrkWBYHSITgADSAIRT9aAUEAQIbBMNloYkHc1lAGH4EFREDAgBvyZBpLEwrwvQAAAAAAAQAAgAAAAOsXNPOkAKHinn1gRoivtCs8e/e0FYwYZByN2xWcmf1TEDQM8QAnkevLB6EgAAAAAAAAAABdgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgnIQDKnxSuJ6rFDCGpSghDt7+nfbZqWBWt45ilfc4bErQ4dMonMlwiBZYVesYaF95BwuRuz5J2k3fcMBcl3bKmgKAgHgCQYBAd8HAbFoAeBjUdop2gnOw9gEwatXEg/JvADIbTyiAfziiyiuwEhLADKXrPRynNkv9GlWfEX/d1LbT1FD4UXo/DWX5p81QD/R0HK7begGK8M2AAAXbq04dgTA6RCcwAgB7RjSFwIAAAAAAAAAAAAAAAAAD0JAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAFSQopo5GzW/93YKmR1LWu54uMvkRuBqK8b9KUgFxRnlwAqSFFNHI2a3/u7BUyOpa13PFxl8iNwNRXjfpSkAuKM8tCwGxaAFSQopo5GzW/93YKmR1LWu54uMvkRuBqK8b9KUgFxRnlwA8DGo7RTtBOdh7AJg1auJB+TeAGQ2nlEA/nFFlFdgJCVB3NZQABikoigAAF26sgVsEwOkQhMAKAc1L8WDigBlL1no5TmyX+jSrPiL/u6ltp6ih8KL0fhrL80+aoB/o4AAAAAAAAAAAAAAAAAHoSAAAAAAAAAAAAAAAAAAAAAAQAqSFFNHI2a3/u7BUyOpa13PFxl8iNwNRXjfpSkAuKM8tCwAA");

        assert!(matches!(
            parse_token_transaction(&tx, &description, TokenWalletVersion::Tip3v3).unwrap(),
            TokenWalletTransaction::OutgoingTransfer(a) if matches!(a.to, TransferRecipient::TokenWallet(_))
        ));
    }

    #[test]
    fn test_parse_incoming_transfer() {
        let (tx, description) = parse_transaction("te6ccgECCwEAAn4AA7d8pes9HKc2S/0aVZ8Rf93UttPUUPhRej8NZfmnzVAP9HAAALt1bZRAGBQoWWE11kL6dy/rc17Pb+y5GPGOMwtHXfUpmAfLiZBwAACydC5gGBYHSIVgADSAMt4wKAUEAQIdBMf4JkkHK7bemIAuP1sRAwIAb8mHoSBMFFhAAAAAAAAEAAIAAAADP+Ts4Qh/QhuWIOvCaHwME9511EJ6C72woKICsN947BxAUBYMAJ5L1uwdXxQAAAAAAAAAAX4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIJy8qOA5vv341sfhzftSqNs/G66PvpQ+QAxLSRo88qdaGlXBAKr4nKvE6BzA+luIJ+6jZo3czvgOH3/Y1+Ws+6xVwIB4AgGAQHfBwCxaAGUvWejlObJf6NKs+Iv+7qW2nqKHwovR+GsvzT5qgH+jwAqSFFNHI2a3/u7BUyOpa13PFxl8iNwNRXjfpSkAuKM8tBstnmIBhRYYAAAF26tsogEwOkQrEABsWgB4GNR2inaCc7D2ATBq1cSD8m8AMhtPKIB/OKLKK7ASEsAMpes9HKc2S/0aVZ8Rf93UttPUUPhRej8NZfmnzVAP9HQcrtt6AYrwzYAABdurTh2BMDpEJzACQHtGNIXAgAAAAAAAAAAAAAAAAAPQkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAVJCimjkbNb/3dgqZHUta7ni4y+RG4Gorxv0pSAXFGeXACpIUU0cjZrf+7sFTI6lrXc8XGXyI3A1FeN+lKQC4ozy0KAAA=");

        assert!(matches!(
            parse_token_transaction(&tx, &description, TokenWalletVersion::Tip3v3).unwrap(),
            TokenWalletTransaction::IncomingTransfer(_)
        ));
    }

    #[test]
    fn test_parse_send_transfer_to_recipient() {
        let (tx, description) = parse_transaction("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");

        assert!(matches!(
            parse_token_transaction(&tx, &description, TokenWalletVersion::Tip3v3).unwrap(),
            TokenWalletTransaction::OutgoingTransfer(a) if matches!(a.to, TransferRecipient::OwnerWallet(_))
        ));
    }

    #[test]
    fn test_parse_swap() {
        let (tx, description) = parse_transaction("te6ccgECDQEAAx4AA7V/AxqO0U7QTnYewCYNWriQfk3gBkNp5RAP5xRZRXYCQlAAAK8wDBUYEgZhXilMhb8uwySppSot4mIjr0gv3SETJXkSpo1fNtPQAACvL/vetDYFZ2wQADR//SVoBQQBAhcETQkHc1lAGH5JaxEDAgBvyZRshEw2dnwAAAAAAAQAAgAAAALltNr4qYJCC5/34YbNvyKcqgqDBCXdRgOzhnR40LLkaEEQQRQAnkfA7B6EgAAAAAAAAAABbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgnJyFRYUCdbm/iIPBBrBh1nQvDRUv4iVZ/TPXsafdMGq7iwcTZXDAFF+tOJ0kZZV41JVZ/IFqG20VsHpSYsLRlDmAgHgCgYBAd8HAbFoAeBjUdop2gnOw9gEwatXEg/JvADIbTyiAfziiyiuwEhLADOcXDcMUS0fCqCF6CrhQZyn2MQ4TEQF7IDBOoLlzsWDUHLFXNQGNnbSAAAV5gGCowTArO2CwAgB7S4oiKoAAAAAAAAAAAAAAAAAmJaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAFSQopo5GzW/93YKmR1LWu54uMvkRuBqK8b9KUgFxRnlwAqSFFNHI2a3/u7BUyOpa13PFxl8iNwNRXjfpSkAuKM8uCQFDgAvpSKEmcdsAU50DME0ul92s65jErkbosgMW7ZfKyelfEAwBsWgBUkKKaORs1v/d2CpkdS1rueLjL5EbgaivG/SlIBcUZ5cAPAxqO0U7QTnYewCYNWriQfk3gBkNp5RAP5xRZRXYCQlQdzWUAAYsZKwAABXmAMuIBMCs7W7ACwHNEEfJBAAAAAAAAAAAAAAAAACYloAAAAAAAAAAAAAAAAAAAAAAgBUkKKaORs1v/d2CpkdS1rueLjL5EbgaivG/SlIBcUZ5cAF9KRQkzjtgCnOgZgml0vu1nXMYlcjdFkBi3bL5WT0r4gwAKGLH29AUH5aUHpmCISLU2U5gJYC7");

        assert!(matches!(
            parse_token_transaction(&tx, &description, TokenWalletVersion::Tip3v3).unwrap(),
            TokenWalletTransaction::SwapBack(_)
        ));
    }

    #[test]
    fn test_parse_mint() {
        let (tx, description) = parse_transaction("te6ccgECBwEAAaMAA7V/Dx4joMaXoc3RFiyAn6o7n4HT55z5/QGPim3CCNJXQXAAAK8vTVj4NVj26LQJ+AavyN1HTyfjsnB1V8MYazh2SAaGUfKitkNwAACvL01Y+BYFZ1BAABRzL58IBQQBAhMECOYloBhzL58RAwIAW8AAAAAAAAAAAAAAAAEtRS2kSeULjPfdJ4YfFGEir+G1RruLcPyCFvDGFBOfjgQAnETpaJxAAAAAAAAAAADmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCcmGLc3puHpvUqy9khm0IOdhMB4DZAuyNlJTJCkg0wvMOh6b7MBQnENOWWqV8wO0KnzyqzAm1eeuCWS1jgX4RNrUBAaAGANdoAEC3zK80W70FBnMN7CWF5ai6t7ZNfr6N19g9kzzkIx83ADw8eI6DGl6HN0RYsgJ+qO5+B0+ec+f0Bj4ptwgjSV0FzmJaAAYUWGAAABXl6TENBsCs6fAFn+ergAAAAAAAAAAN4Lazp2QAAEA=");

        assert!(matches!(
            parse_token_transaction(&tx, &description, TokenWalletVersion::Tip3v3).unwrap(),
            TokenWalletTransaction::Accept(_)
        ));
    }

    #[test]
    fn test_parse_bounced_tokens_transfer() {
        let (tx, description) = parse_transaction("te6ccgECCQEAAiEAA7V9jKvgMYxeLukedeW/PRr7QyRzEpkal33nb9KfgpelA3AAAO1mmxCMEy4UbEGiIQKVpE2nzO2Ar32k7H36ni1NMpxrcPorUNuwAADtZo+e3BYO9BHwADRwGMkIBQQBAhcMSgkCmI36GG92AhEDAgBvyYehIEwUWEAAAAAAAAQAAgAAAAKLF5Ge7DorMQ9dbEzZTgWK7Jiugap8s4dRpkiQl7CNEEBQFgwAnkP1TAqiBAAAAAAAAAAAtgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgnIBZa/nTbAD2Vcr8A6p+uT7XD4tLowmBLZEuIHLxU1zbeHGgHFi5dfeWnrNgtL3FHE6zw6ysjTJJI3LFFDAgPi3AgHgCAYBAd8HALFoAbGVfAYxi8XdI868t+ejX2hkjmJTI1LvvO36U/BS9KBvABgzjiRJUfoXsV99CuD/WnKK4QN5mlferMiVbk0Y3Jc3ECddFmAGFFhgAAAdrNNiEYTB3oI+QAD5WAHF6/YBDYNj7TABzedO3/4+ENpaE0PhwRx5NFYisFNfpQA2Mq+AxjF4u6R515b89GvtDJHMSmRqXfedv0p+Cl6UDdApiN+gBhRYYAAAHazSjHIEwd6CFH////+MaQuBAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAEA=");

        assert!(matches!(
            parse_token_transaction(&tx, &description, TokenWalletVersion::Tip3v4).unwrap(),
            TokenWalletTransaction::TransferBounced(_)
        ));
    }
}
