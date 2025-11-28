use std::convert::TryFrom;

use anyhow::Result;
use num_bigint::BigUint;
use once_cell::race::OnceBox;
use ton_block::{Deserializable, MsgAddressInt};
use ton_types::{SliceData, UInt256};

use nekoton_abi::*;
use nekoton_contracts::tip4_1::nft_contract;
use nekoton_contracts::{old_tip3, tip3_1};

use crate::core::jetton_wallet::{
    JETTON_BURN_NOTIFICATION_OPCODE, JETTON_INTERNAL_TRANSFER_OPCODE, JETTON_TRANSFER_OPCODE,
};
use crate::core::models::*;
use crate::core::ton_wallet::{MultisigType, WalletType};

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

    for version in [TokenWalletVersion::OldTip3v4, TokenWalletVersion::Tip3] {
        let functions = TokenWalletFunctions::for_version(version);

        if function_id == functions.transfer_to_wallet.input_id {
            let inputs = functions
                .transfer_to_wallet
                .decode_input(payload, true, false)
                .ok()?;

            return TokenOutgoingTransfer::try_from((
                InputMessage(inputs),
                TransferType::ByTokenWalletAddress,
                version,
            ))
            .map(KnownPayload::TokenOutgoingTransfer)
            .ok();
        } else if function_id == functions.transfer.input_id {
            let inputs = functions.transfer.decode_input(payload, true, false).ok()?;

            return TokenOutgoingTransfer::try_from((
                InputMessage(inputs),
                TransferType::ByOwnerWalletAddress,
                version,
            ))
            .map(KnownPayload::TokenOutgoingTransfer)
            .ok();
        } else if function_id == functions.burn.input_id {
            let inputs = functions.burn.decode_input(payload, true, false).ok()?;

            return TokenSwapBack::try_from((InputMessage(inputs), version))
                .map(KnownPayload::TokenSwapBack)
                .ok();
        }
    }

    None
}

pub fn parse_jetton_payload(payload: ton_types::SliceData) -> Option<KnownPayload> {
    let mut payload = payload;

    let opcode = payload.get_next_u32().ok()?;
    if opcode != JETTON_TRANSFER_OPCODE {
        return None;
    }

    let _query_id = payload.get_next_u64().ok()?;

    let mut amount = ton_block::Grams::default();
    amount.read_from(&mut payload).ok()?;

    let mut dst_addr = MsgAddressInt::default();
    dst_addr.read_from(&mut payload).ok()?;

    Some(KnownPayload::JettonOutgoingTransfer(
        JettonOutgoingTransfer {
            to: dst_addr,
            tokens: BigUint::from(amount.as_u128()),
        },
    ))
}

pub fn parse_transaction_additional_info(
    tx: &ton_block::Transaction,
    wallet_type: WalletType,
) -> Option<TransactionAdditionalInfo> {
    let in_msg = tx.in_msg.as_ref()?.read_struct().ok()?;

    let int_header = match in_msg.header() {
        ton_block::CommonMsgInfo::ExtInMsgInfo(_) => {
            let (recipient, known_payload, method) = match wallet_type {
                WalletType::WalletV3 | WalletType::HighloadWalletV2 | WalletType::EverWallet => {
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
                WalletType::WalletV3R1
                | WalletType::WalletV3R2
                | WalletType::WalletV4R1
                | WalletType::WalletV4R2
                | WalletType::WalletV5R1 => {
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

                    let known_payload = out_msg.body().and_then(parse_jetton_payload);

                    (
                        Some(recipient.clone()),
                        known_payload,
                        WalletInteractionMethod::TonWalletTransfer,
                    )
                }
                WalletType::Multisig(multisig_type) => {
                    let method = parse_multisig_transaction_impl(multisig_type, in_msg, tx)?;
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
                        }) => (
                            Some(dest.clone()),
                            parse_payload(ton_types::SliceData::load_cell_ref(payload).ok()?),
                        ),
                        _ => (None, None),
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
            .decode_input(body, true, false)
            .ok()?;

        DePoolOnRoundCompleteNotification::try_from(InputMessage(inputs))
            .map(TransactionAdditionalInfo::DePoolOnRoundComplete)
            .ok()
    } else if function_id == depool_notifications.receive_answer.input_id {
        let inputs = depool_notifications
            .receive_answer
            .decode_input(body, true, false)
            .ok()?;

        DePoolReceiveAnswerNotification::try_from(InputMessage(inputs))
            .map(TransactionAdditionalInfo::DePoolReceiveAnswer)
            .ok()
    } else if function_id == token_notifications.notify_wallet_deployed.input_id {
        let inputs = token_notifications
            .notify_wallet_deployed
            .decode_input(body, true, false)
            .ok()?;

        TokenWalletDeployedNotification::try_from(InputMessage(inputs))
            .map(TransactionAdditionalInfo::TokenWalletDeployed)
            .ok()
    } else if function_id == JettonNotify::FUNCTION_ID {
        JettonNotify::decode_body(body).map(TransactionAdditionalInfo::JettonNotify)
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

struct JettonNotify;

impl JettonNotify {
    const FUNCTION_ID: u32 = 0x7362d09c;

    fn decode_body(data: ton_types::SliceData) -> Option<JettonIncomingTransfer> {
        let mut payload = data;

        let function_id = payload.get_next_u32().ok()?;
        assert_eq!(function_id, Self::FUNCTION_ID);

        let _query_id = payload.get_next_u64().ok()?;

        let mut amount = ton_block::Grams::default();
        amount.read_from(&mut payload).ok()?;

        let mut sender = MsgAddressInt::default();
        sender.read_from(&mut payload).ok()?;

        Some(JettonIncomingTransfer {
            from: sender,
            tokens: BigUint::from(amount.as_u128()),
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

pub fn parse_multisig_transaction(
    multisig_type: MultisigType,
    tx: &ton_block::Transaction,
) -> Option<MultisigTransaction> {
    let in_msg = tx.in_msg.as_ref()?.read_struct().ok()?;
    if !matches!(in_msg.header(), ton_block::CommonMsgInfo::ExtInMsgInfo(_)) {
        return None;
    }
    parse_multisig_transaction_impl(multisig_type, in_msg, tx)
}

fn parse_multisig_transaction_impl(
    multisig_type: MultisigType,
    in_msg: ton_block::Message,
    tx: &ton_block::Transaction,
) -> Option<MultisigTransaction> {
    const PUBKEY_OFFSET: usize = 1 + ed25519_dalek::SIGNATURE_LENGTH * 8 + 1;
    const PUBKEY_LENGTH: usize = 256;
    const TIME_LENGTH: usize = 64;
    const EXPIRE_LENGTH: usize = 32;

    let body = in_msg.body()?;
    let function_id = {
        let mut body = body.clone();

        // Shift body by Maybe(signature), Maybe(pubkey), time and expire
        body.move_by(PUBKEY_OFFSET + PUBKEY_LENGTH + TIME_LENGTH + EXPIRE_LENGTH)
            .ok()?;

        read_function_id(&body).ok()?
    };

    let parse_tx_input = |function: &ton_abi::Function,
                          mut body: ton_types::SliceData|
     -> Option<(ton_types::UInt256, InputMessage)> {
        let inputs = function.decode_input(body.clone(), false, false).ok()?;
        body.move_by(PUBKEY_OFFSET).ok()?;
        let custodian = body.get_next_hash().ok()?;
        Some((custodian, InputMessage(inputs)))
    };

    let parse_tx_full = |function: &ton_abi::Function,
                         body: ton_types::SliceData|
     -> Option<(ton_types::UInt256, ContractCall)> {
        let (custodian, InputMessage(inputs)) = parse_tx_input(function, body)?;
        let outputs = function.parse(tx).ok()?;
        Some((custodian, ContractCall { inputs, outputs }))
    };

    let functions = MultisigFunctions::instance(multisig_type);

    if function_id == functions.send_transaction.input_id {
        let inputs = functions
            .send_transaction
            .decode_input(body, false, false)
            .ok()?;
        MultisigSendTransaction::try_from(InputMessage(inputs))
            .map(MultisigTransaction::Send)
            .ok()
    } else if function_id == functions.submit_transaction.input_id {
        let (custodian, value) = parse_tx_full(functions.submit_transaction, body)?;
        MultisigSubmitTransaction::try_from((custodian, value))
            .map(MultisigTransaction::Submit)
            .ok()
    } else if function_id == functions.confirm_transaction.input_id {
        let (custodian, value) = parse_tx_input(functions.confirm_transaction, body)?;
        MultisigConfirmTransaction::try_from((custodian, value))
            .map(MultisigTransaction::Confirm)
            .ok()
    } else if let Some(functions) = &functions.update_functions {
        if function_id == functions.submit_update.input_id {
            let (custodian, value) = parse_tx_full(functions.submit_update, body)?;
            MultisigSubmitUpdate::try_from((custodian, value))
                .map(MultisigTransaction::SubmitUpdate)
                .ok()
        } else if function_id == functions.confirm_update.input_id {
            let (custodian, value) = parse_tx_input(functions.confirm_update, body)?;
            MultisigConfirmUpdate::try_from((custodian, value))
                .map(MultisigTransaction::ConfirmUpdate)
                .ok()
        } else if function_id == functions.execute_update.input_id {
            let (custodian, value) = parse_tx_input(functions.execute_update, body)?;
            MultisigExecuteUpdate::try_from((custodian, value))
                .map(MultisigTransaction::ExecuteUpdate)
                .ok()
        } else {
            None
        }
    } else {
        None
    }
}

struct MultisigFunctions {
    send_transaction: &'static ton_abi::Function,
    submit_transaction: &'static ton_abi::Function,
    confirm_transaction: &'static ton_abi::Function,
    update_functions: Option<UpdateFunctions>,
}

struct UpdateFunctions {
    submit_update: &'static ton_abi::Function,
    confirm_update: &'static ton_abi::Function,
    execute_update: &'static ton_abi::Function,
}

impl MultisigFunctions {
    fn instance(multisig_type: MultisigType) -> &'static Self {
        use nekoton_contracts::wallets::{multisig, multisig2};

        static OLD_FUNCTIONS: OnceBox<MultisigFunctions> = OnceBox::new();
        static NEW_FUNCTIONS: OnceBox<MultisigFunctions> = OnceBox::new();

        match multisig_type {
            ty if ty.is_multisig2() => NEW_FUNCTIONS.get_or_init(|| {
                Box::new(MultisigFunctions {
                    send_transaction: multisig2::send_transaction(),
                    submit_transaction: multisig2::submit_transaction(),
                    confirm_transaction: multisig2::confirm_transaction(),
                    update_functions: Some(UpdateFunctions {
                        submit_update: multisig2::submit_update(),
                        confirm_update: multisig2::confirm_update(),
                        execute_update: multisig2::execute_update(),
                    }),
                })
            }),
            _ => OLD_FUNCTIONS.get_or_init(|| {
                Box::new(MultisigFunctions {
                    send_transaction: multisig::send_transaction(),
                    submit_transaction: multisig::submit_transaction(),
                    confirm_transaction: multisig::confirm_transaction(),
                    update_functions: None,
                })
            }),
        }
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

impl TryFrom<(UInt256, ContractCall)> for MultisigSubmitUpdate {
    type Error = UnpackerError;

    fn try_from((custodian, value): (UInt256, ContractCall)) -> Result<Self, Self::Error> {
        use nekoton_contracts::wallets::multisig2;

        let input: multisig2::SubmitUpdateParams = value.inputs.unpack()?;
        let output: multisig2::SubmitUpdateOutput = value.outputs.unpack()?;

        Ok(Self {
            custodian,
            new_code_hash: input.code_hash,
            new_owners: input.owners.is_some(),
            new_req_confirms: input.req_confirms.is_some(),
            new_lifetime: input.lifetime.is_some(),
            update_id: output.update_id,
        })
    }
}

impl TryFrom<(UInt256, InputMessage)> for MultisigConfirmUpdate {
    type Error = UnpackerError;

    fn try_from((custodian, input): (UInt256, InputMessage)) -> Result<Self, Self::Error> {
        use nekoton_contracts::wallets::multisig2;

        let input: multisig2::ConfirmUpdateParams = input.0.unpack()?;
        Ok(Self {
            custodian,
            update_id: input.update_id,
        })
    }
}

impl TryFrom<(UInt256, InputMessage)> for MultisigExecuteUpdate {
    type Error = UnpackerError;

    fn try_from((custodian, input): (UInt256, InputMessage)) -> Result<Self, Self::Error> {
        use nekoton_contracts::wallets::multisig2;

        let input: multisig2::ExecuteUpdateParams = input.0.unpack()?;
        Ok(Self {
            custodian,
            update_id: input.update_id,
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

    let in_msg = tx.in_msg.as_ref()?.read_struct().ok()?;

    let mut body = in_msg.body()?;
    let function_id = read_function_id(&body).ok()?;

    let header = in_msg.int_header()?;

    let functions = TokenWalletFunctions::for_version(version);

    if header.bounced {
        body.move_by(32).ok()?;
        let function_id = read_function_id(&body).ok()?;
        body.move_by(32).ok()?;

        if function_id == functions.accept_transfer.input_id {
            return Some(TokenWalletTransaction::TransferBounced(
                body.get_next_u128().ok()?.into(),
            ));
        }

        if function_id == functions.accept_burn.input_id {
            Some(TokenWalletTransaction::SwapBackBounced(
                body.get_next_u128().ok()?.into(),
            ))
        } else {
            None
        }
    } else if function_id == functions.accept_mint.input_id {
        let inputs = functions.accept_mint.decode_input(body, true, false).ok()?;

        Accept::try_from((InputMessage(inputs), version))
            .map(|Accept { tokens }| TokenWalletTransaction::Accept(tokens))
            .ok()
    } else if function_id == functions.transfer_to_wallet.input_id {
        let inputs = functions
            .transfer_to_wallet
            .decode_input(body, true, false)
            .ok()?;

        TokenOutgoingTransfer::try_from((
            InputMessage(inputs),
            TransferType::ByTokenWalletAddress,
            version,
        ))
        .map(TokenWalletTransaction::OutgoingTransfer)
        .ok()
    } else if function_id == functions.transfer.input_id {
        let inputs = functions.transfer.decode_input(body, true, false).ok()?;

        TokenOutgoingTransfer::try_from((
            InputMessage(inputs),
            TransferType::ByOwnerWalletAddress,
            version,
        ))
        .map(TokenWalletTransaction::OutgoingTransfer)
        .ok()
    } else if function_id == functions.accept_transfer.input_id {
        let inputs = functions
            .accept_transfer
            .decode_input(body, true, false)
            .ok()?;

        TokenIncomingTransfer::try_from((InputMessage(inputs), version))
            .map(TokenWalletTransaction::IncomingTransfer)
            .ok()
    } else if function_id == functions.burn.input_id {
        let inputs = functions.burn.decode_input(body, true, false).ok()?;

        TokenSwapBack::try_from((InputMessage(inputs), version))
            .map(TokenWalletTransaction::SwapBack)
            .ok()
    } else {
        None
    }
}

pub fn parse_jetton_transaction(
    tx: &ton_block::Transaction,
    description: &ton_block::TransactionDescrOrdinary,
) -> Option<JettonWalletTransaction> {
    const STANDART_JETTON_CELLS: usize = 0;
    const STANDART_JETTON_BURN_CELLS: usize = 1;
    const MINTLESS_JETTON_CELLS: usize = 2;

    if description.aborted {
        return None;
    }

    let in_msg = tx.in_msg.as_ref()?.read_struct().ok()?;

    // Workaround to extract body since we don`t store the type in message
    let mut body = {
        let body = in_msg.body()?;
        let refs = body.remaining_references();

        match refs {
            MINTLESS_JETTON_CELLS => {
                let cell = body.reference_opt(1)?;
                SliceData::load_cell(cell).ok()?
            }
            STANDART_JETTON_CELLS | STANDART_JETTON_BURN_CELLS => body,
            _ => return None,
        }
    };

    let opcode = body.get_next_u32().ok()?;

    if opcode != JETTON_TRANSFER_OPCODE
        && opcode != JETTON_INTERNAL_TRANSFER_OPCODE
        && opcode != JETTON_BURN_NOTIFICATION_OPCODE
    {
        return None;
    }

    // Skip query id
    body.move_by(64).ok()?;

    let mut grams = ton_block::Grams::default();
    grams.read_from(&mut body).ok()?;

    let amount = BigUint::from(grams.as_u128());

    let mut addr = MsgAddressInt::default();
    addr.read_from(&mut body).ok()?;

    match opcode {
        JETTON_TRANSFER_OPCODE => Some(JettonWalletTransaction::Transfer(JettonOutgoingTransfer {
            to: addr,
            tokens: amount,
        })),
        JETTON_INTERNAL_TRANSFER_OPCODE => Some(JettonWalletTransaction::InternalTransfer(
            JettonIncomingTransfer {
                from: addr,
                tokens: amount,
            },
        )),
        JETTON_BURN_NOTIFICATION_OPCODE => Some(JettonWalletTransaction::BurnNotification(
            JettonBurnNotification {
                from: addr,
                tokens: amount,
            },
        )),
        _ => None,
    }
}

struct NftFunctions {
    transfer: &'static ton_abi::Function,
    change_owner: &'static ton_abi::Function,
    change_manager: &'static ton_abi::Function,
}

impl NftFunctions {
    pub fn instance() -> &'static Self {
        static IDS: OnceBox<NftFunctions> = OnceBox::new();
        IDS.get_or_init(|| {
            Box::new(Self {
                transfer: nft_contract::transfer(),
                change_owner: nft_contract::change_owner(),
                change_manager: nft_contract::change_manager(),
            })
        })
    }
}

pub fn parse_nft_transaction(
    tx: &ton_block::Transaction,
    description: &ton_block::TransactionDescrOrdinary,
) -> Option<NftTransaction> {
    if description.aborted {
        return None;
    }

    let in_msg = tx.in_msg.as_ref()?.read_struct().ok()?;

    let body = in_msg.body()?;
    let function_id = read_function_id(&body).ok()?;

    let functions = NftFunctions::instance();

    if function_id == functions.transfer.input_id {
        let inputs = functions.transfer.decode_input(body, true, false).ok()?;

        IncomingNftTransfer::try_from(InputMessage(inputs))
            .map(NftTransaction::Transfer)
            .ok()
    } else if function_id == functions.change_owner.input_id {
        let inputs = functions
            .change_owner
            .decode_input(body, true, false)
            .ok()?;

        IncomingChangeOwner::try_from(InputMessage(inputs))
            .map(NftTransaction::ChangeOwner)
            .ok()
    } else if function_id == functions.change_manager.input_id {
        let inputs = functions
            .change_manager
            .decode_input(body, true, false)
            .ok()?;

        IncomingChangeManager::try_from(InputMessage(inputs))
            .map(NftTransaction::ChangeManager)
            .ok()
    } else {
        None
    }
}

struct TokenWalletFunctions {
    // Incoming
    accept_mint: &'static ton_abi::Function,
    // Incoming
    transfer: &'static ton_abi::Function,
    // Incoming
    transfer_to_wallet: &'static ton_abi::Function,
    // Incoming
    accept_transfer: &'static ton_abi::Function,
    // Incoming
    burn: &'static ton_abi::Function,
    // Outgoing
    accept_burn: &'static ton_abi::Function,
}

impl TokenWalletFunctions {
    pub fn for_version(version: TokenWalletVersion) -> &'static TokenWalletFunctions {
        match version {
            TokenWalletVersion::OldTip3v4 => {
                static IDS: OnceBox<TokenWalletFunctions> = OnceBox::new();
                IDS.get_or_init(|| {
                    Box::new(Self {
                        accept_mint: old_tip3::token_wallet_contract::accept(),
                        transfer: old_tip3::token_wallet_contract::transfer_to_recipient(),
                        transfer_to_wallet: old_tip3::token_wallet_contract::transfer(),
                        accept_transfer: old_tip3::token_wallet_contract::internal_transfer(),
                        burn: old_tip3::token_wallet_contract::burn_by_owner(),
                        accept_burn: old_tip3::root_token_contract::tokens_burned(),
                    })
                })
            }
            TokenWalletVersion::Tip3 => {
                static IDS: OnceBox<TokenWalletFunctions> = OnceBox::new();
                IDS.get_or_init(|| {
                    Box::new(Self {
                        accept_mint: tip3_1::token_wallet_contract::accept_mint(),
                        transfer: tip3_1::token_wallet_contract::transfer(),
                        transfer_to_wallet: tip3_1::token_wallet_contract::transfer_to_wallet(),
                        accept_transfer: tip3_1::token_wallet_contract::accept_transfer(),
                        burn: tip3_1::token_wallet_contract::burnable::burn(),
                        accept_burn: tip3_1::root_token_contract::accept_burn(),
                    })
                })
            }
        }
    }
}

impl TryFrom<(InputMessage, TokenWalletVersion)> for TokenSwapBack {
    type Error = UnpackerError;

    fn try_from((value, version): (InputMessage, TokenWalletVersion)) -> Result<Self, Self::Error> {
        Ok(match version {
            TokenWalletVersion::OldTip3v4 => {
                let input: old_tip3::token_wallet_contract::BurnByOwnerInputs = value.0.unpack()?;

                Self {
                    tokens: input.tokens,
                    callback_address: input.callback_address,
                    callback_payload: input.callback_payload,
                }
            }
            TokenWalletVersion::Tip3 => {
                let input: tip3_1::token_wallet_contract::burnable::BurnInputs =
                    value.0.unpack()?;

                Self {
                    tokens: input.amount,
                    callback_address: input.callback_to,
                    callback_payload: input.payload,
                }
            }
        })
    }
}

struct Accept {
    tokens: BigUint,
}

impl TryFrom<(InputMessage, TokenWalletVersion)> for Accept {
    type Error = UnpackerError;

    fn try_from((value, version): (InputMessage, TokenWalletVersion)) -> Result<Self, Self::Error> {
        Ok(match version {
            TokenWalletVersion::OldTip3v4 => {
                let input: old_tip3::token_wallet_contract::AcceptInputs = value.0.unpack()?;
                Self {
                    tokens: input.tokens,
                }
            }
            TokenWalletVersion::Tip3 => {
                let input: tip3_1::token_wallet_contract::AcceptMintInputs = value.0.unpack()?;
                Self {
                    tokens: input.amount,
                }
            }
        })
    }
}

enum TransferType {
    ByOwnerWalletAddress,
    ByTokenWalletAddress,
}

impl TryFrom<(InputMessage, TransferType, TokenWalletVersion)> for TokenOutgoingTransfer {
    type Error = UnpackerError;

    fn try_from(
        (value, transfer_type, version): (InputMessage, TransferType, TokenWalletVersion),
    ) -> Result<Self, Self::Error> {
        Ok(match version {
            TokenWalletVersion::OldTip3v4 => {
                match transfer_type {
                    // "transferToRecipient"
                    TransferType::ByOwnerWalletAddress => {
                        let input: old_tip3::token_wallet_contract::TransferToRecipientInputs =
                            value.0.unpack()?;
                        Self {
                            to: TransferRecipient::OwnerWallet(input.recipient_address),
                            tokens: input.tokens,
                            payload: input.payload,
                        }
                    }
                    // "transfer
                    TransferType::ByTokenWalletAddress => {
                        let input: old_tip3::token_wallet_contract::TransferInputs =
                            value.0.unpack()?;
                        Self {
                            to: TransferRecipient::TokenWallet(input.to),
                            tokens: input.tokens,
                            payload: input.payload,
                        }
                    }
                }
            }
            TokenWalletVersion::Tip3 => {
                match transfer_type {
                    // "transfer"
                    TransferType::ByOwnerWalletAddress => {
                        let input: tip3_1::token_wallet_contract::TransferInputs =
                            value.0.unpack()?;
                        Self {
                            to: TransferRecipient::OwnerWallet(input.recipient),
                            tokens: input.amount,
                            payload: input.payload,
                        }
                    }
                    // "transferToWallet"
                    TransferType::ByTokenWalletAddress => {
                        let input: tip3_1::token_wallet_contract::TransferToWalletInputs =
                            value.0.unpack()?;
                        Self {
                            to: TransferRecipient::TokenWallet(input.recipient_token_wallet),
                            tokens: input.amount,
                            payload: input.payload,
                        }
                    }
                }
            }
        })
    }
}

impl TryFrom<(InputMessage, TokenWalletVersion)> for TokenIncomingTransfer {
    type Error = UnpackerError;

    fn try_from((value, version): (InputMessage, TokenWalletVersion)) -> Result<Self, Self::Error> {
        Ok(match version {
            TokenWalletVersion::OldTip3v4 => {
                let input: old_tip3::token_wallet_contract::InternalTransferInputs =
                    value.0.unpack()?;

                Self {
                    tokens: input.tokens,
                    sender_address: input.sender_address,
                }
            }
            TokenWalletVersion::Tip3 => {
                let input: tip3_1::token_wallet_contract::AcceptTransferInputs =
                    value.0.unpack()?;

                Self {
                    tokens: input.amount,
                    sender_address: input.sender,
                }
            }
        })
    }
}

impl TryFrom<InputMessage> for IncomingNftTransfer {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> std::result::Result<Self, Self::Error> {
        let input: nft_contract::TransferInputs = value.0.unpack()?;

        Ok(Self {
            send_gas_to: input.send_gas_to,
            to: input.to,
        })
    }
}

impl TryFrom<InputMessage> for IncomingChangeManager {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> std::result::Result<Self, Self::Error> {
        let input: nft_contract::ChangeManagerInputs = value.0.unpack()?;

        Ok(Self {
            send_gas_to: input.send_gas_to,
            new_manager: input.new_manager,
        })
    }
}

impl TryFrom<InputMessage> for IncomingChangeOwner {
    type Error = UnpackerError;

    fn try_from(value: InputMessage) -> std::result::Result<Self, Self::Error> {
        let input: nft_contract::ChangeOwnerInputs = value.0.unpack()?;

        Ok(Self {
            send_gas_to: input.send_gas_to,
            new_owner: input.new_owner,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::core::ton_wallet::MultisigType;

    use nekoton_abi::num_traits::ToPrimitive;
    use ton_block::{Deserializable, Transaction, TransactionDescrOrdinary};

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
    fn test_parse_wallet_v3_token_transfer_with_payload() {
        let tx = Transaction::construct_from_base64("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").unwrap();
        println!("tx: {tx:#?}");

        let description = match tx.description.read_struct() {
            Ok(ton_block::TransactionDescr::Ordinary(description)) => description,
            _ => panic!(),
        };
        println!("description: {description:#?}");

        let parsed = parse_token_transaction(&tx, &description, TokenWalletVersion::Tip3);
        println!("parsed tx: {parsed:#?}");
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

    #[test]
    fn test_parse_wallet_v5r1_transfer() {
        let (tx, description) = parse_transaction("te6ccgECDgEAAroAA7V6PzxB5ur5JLcojkw57D91dcch0SdJBkRg11onChvcQxAAAuqQo7KQGfOICr+MryG/HTeCGLoHvR2QzQp8l/VW7Jy5KteDKoNgAALqkJdMvBZ0b1RwADRmUxQIBQQBAg8MQoYY8SmEQAMCAG/JhfBQTA/WGAAAAAAAAgAAAAAAAxZIaTNMW1cxmByM5WsWV9cxExzB5+1s+b7Uz5613xWmQNAtXACdQmljE4gAAAAAAAAAACPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIACCcp/sV0iKg0YadasmKflOuBQl9+BT1AMGK8jDUAHzabPWEAUiOhXPDSZMLX8X/WQ0jZRy1Ef+OW9TZFgZ7OoiSM4CAeAIBgEB3wcBsWgBR+eIPN1fJJblEcmHPYfurrjkOiTpIMiMGutE4UN7iGMABaelQoOWDtcjd5wKID6i0sUbGwEsUr2tFotsGs7AiEdQUQ/0AAYP1jQAAF1SFHZSBM6N6o7ACwHliAFH54g83V8kluURyYc9h+6uuOQ6JOkgyIwa60ThQ3uIYgObSztz///4izo3vDAAACqUsU/LVK+ma1KSpaW5p+h9917oIw6a7Txpn/VJg/WB7C5dJQYSdVOvNFZvNMz1vvv5wMwo33jnWdrh1jaHQJXGBQkCCg7DyG0DDQoBaGIAC09KhQcsHa5G7zgUQH1FpYo2NgJYpXtaLRbYNZ2BEI6goh/oAAAAAAAAAAAAAAAAAAELAbIPin6lAAAAAAAAAABUUC0RQAgAcgwTrCsIXFRhmQTVWMIpgapb1R1i6mXzRjfAhiAa+x8AKPzxB5ur5JLcojkw57D91dcch0SdJBkRg11onChvcQxIHJw4AQwACW7J3GUgAAA=");
        assert!(!description.aborted);

        let wallet_transaction = parse_transaction_additional_info(&tx, WalletType::WalletV5R1);
        assert!(wallet_transaction.is_some());

        if let Some(TransactionAdditionalInfo::WalletInteraction(WalletInteractionInfo {
            recipient,
            known_payload,
            ..
        })) = wallet_transaction
        {
            assert_eq!(
                recipient.unwrap(),
                MsgAddressInt::from_str(
                    "0:169e950a0e583b5c8dde702880fa8b4b146c6c04b14af6b45a2db06b3b02211d"
                )
                .unwrap()
            );

            assert!(known_payload.is_some());

            let payload = known_payload.unwrap();
            if let KnownPayload::JettonOutgoingTransfer(JettonOutgoingTransfer { to, tokens }) =
                payload
            {
                assert_eq!(
                    to,
                    MsgAddressInt::from_str(
                        "0:390609d615842e2a30cc826aac6114c0d52dea8eb17532f9a31be043100d7d8f"
                    )
                    .unwrap()
                );

                assert_eq!(tokens.to_u128().unwrap(), 296400000000);
            }
        }
    }

    #[test]
    fn test_jetton_incoming_transfer() {
        let (tx, description) = parse_transaction("te6ccgECEQEAA18AA7VyIr+K0006cnz63RzDYQCVEwPdJSutXyVs8FkkuI/aUhAAAuqVnc5wMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ0cDmQAFxhZIHoBQQBAhUECQF3khgYYMNQEQMCAG/Jh45gTBQmPAAAAAAABgACAAAABCVSGbb14fUjN0CNk0Gb357AgRdmQAzjvhXKQxQsysyEQNA6FACeQH0MDwXYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCcpCuyJZa+rsW68PLm0COuucbYY14eIvIDQmENZPKyY2kdcLRm1JwTMPyj/1uPSmUxtxqBm0adw5aQV4xl7KOWKwCAeAMBgIB3QkHAQEgCADJSABEV/FaaadOT59bo5hsIBKiYHukpXWr5K2eCySXEftKQwAbKNSc4kliLTF9K6JjcGYPuyWYt/+vqzb6CEDodHcrGBAVsEtIBggjWgAAXVKzuc4Kzo4HMmqZO22AAADJtrLp10ABASAKAatIAERX8Vppp05Pn1ujmGwgEqJge6SldavkrZ4LJJcR+0pDACVnoRAcypBvfVhKhUZM4vfJwlpqV0CQVAZrLvutrEkmhAQGDAMIAABdUrO5zgjOjgcywAsAXnNi0JwAAAGTbWXTrhZIANlGpOcSSxFpi+ldExuDMH3ZLMW//X1Zt9BCB0OjuVjAArFoAFvJbBqvg228UqryRCckJdyJhdWLi/oZ3qOObCPE9jQBAAiK/itNNOnJ8+t0cw2EAlRMD3SUrrV8lbPBZJLiP2lIUBd5IYAGF1LiAABdUrO5zgTOjgcz4A4NAKMXjUUZAAABk21l064WSADZRqTnEksRaYvpXRMbgzB92SzFv/19WbfQQgdDo7lYwQAbKNSc4kliLTF9K6JjcGYPuyWYt/+vqzb6CEDodHcrGAQFAgE0EA8AhwCAErPQiA5lSDe+rCVCoyZxe+ThLTUroEgqAzWXfdbWJJNQAsROplLUCShZxn2kTkyjrdZWWw4ol9ZAosUb+zcNiHf6CEICj0Utek39dAZraCNlF3JZ7QVzRDW+drX9S9XYryt8PWg=");
        assert!(!description.aborted);

        let jetton_transaction = parse_jetton_transaction(&tx, &description).unwrap();

        if let JettonWalletTransaction::InternalTransfer(JettonIncomingTransfer { from, tokens }) =
            jetton_transaction
        {
            assert_eq!(tokens.to_u128().unwrap(), 100);
            assert_eq!(
                from,
                MsgAddressInt::from_str(
                    "0:6ca35273892588b4c5f4ae898dc1983eec9662dffebeacdbe82103a1d1dcac60"
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn test_jetton_dai() {
        let (tx, description) = parse_transaction("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");
        assert!(!description.aborted);

        let jetton_transaction = parse_jetton_transaction(&tx, &description).unwrap();

        if let JettonWalletTransaction::InternalTransfer(JettonIncomingTransfer { from, tokens }) =
            jetton_transaction
        {
            assert_eq!(tokens.to_u128().unwrap(), 100000000000000000);
            assert_eq!(
                from,
                MsgAddressInt::from_str(
                    "0:2cf545d69ef7331c637cbcbaa358c7d58277a1b5713788736d62435dfa050ced"
                )
                .unwrap()
            );
        }
    }
}
