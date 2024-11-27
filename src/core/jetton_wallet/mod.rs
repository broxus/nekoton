use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use nekoton_abi::num_traits::ToPrimitive;
use nekoton_abi::*;
use nekoton_contracts::jetton::{JettonRootData, JettonWalletData};
use nekoton_utils::*;
use num_bigint::{BigInt, BigUint, ToBigInt};
use ton_block::{MsgAddressInt, Serializable};
use ton_types::{BuilderData, IBitstring, SliceData};

use crate::core::models::*;
use crate::core::parsing::*;
use crate::core::transactions_tree::TransactionsTreeStream;
use crate::transport::models::{RawContractState, RawTransaction};
use crate::transport::Transport;

use super::{ContractSubscription, InternalMessage};

pub const JETTON_TRANSFER_OPCODE: u32 = 0x0f8a7ea5;
pub const JETTON_INTERNAL_TRANSFER_OPCODE: u32 = 0x178d4519;

pub struct JettonWallet {
    clock: Arc<dyn Clock>,
    contract_subscription: ContractSubscription,
    handler: Arc<dyn JettonWalletSubscriptionHandler>,
    owner: MsgAddressInt,
    balance: BigUint,
}

impl JettonWallet {
    pub async fn subscribe(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        owner: MsgAddressInt,
        root_token_contract: MsgAddressInt,
        handler: Arc<dyn JettonWalletSubscriptionHandler>,
    ) -> Result<JettonWallet> {
        let state = match transport.get_contract_state(&root_token_contract).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists { .. } => {
                return Err(JettonWalletError::InvalidRootTokenContract.into())
            }
        };
        let state = nekoton_contracts::jetton::RootTokenContract(state.as_context(clock.as_ref()));

        let address = state.get_wallet_address(&owner)?;

        let mut balance = Default::default();
        let contract_subscription = ContractSubscription::subscribe(
            clock.clone(),
            transport,
            address,
            &mut make_contract_state_handler(clock.clone(), &mut balance),
            Some(&mut make_transactions_handler(handler.as_ref())),
        )
        .await?;

        handler.on_balance_changed(balance.clone());

        Ok(Self {
            clock,
            contract_subscription,
            handler,
            owner,
            balance,
        })
    }

    pub fn contract_subscription(&self) -> &ContractSubscription {
        &self.contract_subscription
    }

    pub fn owner(&self) -> &MsgAddressInt {
        &self.owner
    }

    pub fn address(&self) -> &MsgAddressInt {
        self.contract_subscription.address()
    }

    pub fn balance(&self) -> &BigUint {
        &self.balance
    }

    pub fn contract_state(&self) -> &ContractState {
        self.contract_subscription.contract_state()
    }

    pub async fn estimate_min_attached_amount(
        &self,
        amount: BigUint,
        destination: MsgAddressInt,
        remaining_gas_to: MsgAddressInt,
        custom_payload: Option<ton_types::Cell>,
        callback_value: BigUint,
        callback_payload: Option<ton_types::Cell>,
    ) -> Result<u64> {
        const FEE_MULTIPLIER: u128 = 2;

        // Prepare internal message
        let internal_message = self.prepare_transfer(
            amount,
            destination,
            remaining_gas_to,
            custom_payload,
            callback_value,
            callback_payload,
            0,
        )?;

        let mut message = ton_block::Message::with_int_header(ton_block::InternalMessageHeader {
            src: ton_block::MsgAddressIntOrNone::Some(
                internal_message
                    .source
                    .unwrap_or_else(|| self.owner.clone()),
            ),
            dst: internal_message.destination,
            ..Default::default()
        });

        message.set_body(internal_message.body.clone());

        // Prepare executor
        let transport = self.contract_subscription.transport().clone();
        let config = transport
            .get_blockchain_config(self.clock.as_ref(), true)
            .await?;

        let mut tree = TransactionsTreeStream::new(message, config, transport, self.clock.clone());
        tree.unlimited_account_balance();
        tree.unlimited_message_balance();

        type Err = fn(Option<i32>) -> JettonWalletError;
        let check_exit_code = |tx: &ton_block::Transaction, err: Err| -> Result<()> {
            let descr = tx.read_description()?;
            if descr.is_aborted() {
                let exit_code = match descr {
                    ton_block::TransactionDescr::Ordinary(descr) => match descr.compute_ph {
                        ton_block::TrComputePhase::Vm(phase) => Some(phase.exit_code),
                        ton_block::TrComputePhase::Skipped(_) => None,
                    },
                    _ => None,
                };
                Err(err(exit_code).into())
            } else {
                Ok(())
            }
        };

        let mut attached_amount: u128 = 0;

        // Simulate source transaction
        let source_tx = tree.next().await?.ok_or(JettonWalletError::NoSourceTx)?;
        check_exit_code(&source_tx, JettonWalletError::SourceTxFailed)?;
        attached_amount += source_tx.total_fees.grams.as_u128();

        if source_tx.outmsg_cnt == 0 {
            return Err(JettonWalletError::NoDestTx.into());
        }

        if let Some(message) = tree.peek() {
            if message.state_init().is_some() && message.src_ref() == Some(self.address()) {
                // Simulate first deploy transaction
                // NOTE: we don't need to count attached amount here because of separate `initial_balance`
                let _ = tree.next().await?.ok_or(JettonWalletError::NoDestTx)?;
                //also we ignore non zero exit code for deploy transactions
            }
        }

        tree.retain_message_queue(|message| {
            message.state_init().is_none() && message.src_ref() == Some(self.address())
        });

        if tree.message_queue().len() != 1 {
            return Err(JettonWalletError::NoDestTx.into());
        }

        // Simulate destination transaction
        let dest_tx = tree.next().await?.ok_or(JettonWalletError::NoDestTx)?;
        check_exit_code(&dest_tx, JettonWalletError::DestinationTxFailed)?;
        attached_amount += dest_tx.total_fees.grams.as_u128();

        Ok((attached_amount * FEE_MULTIPLIER) as u64)
    }

    pub fn prepare_transfer(
        &self,
        amount: BigUint,
        destination: MsgAddressInt,
        remaining_gas_to: MsgAddressInt,
        custom_payload: Option<ton_types::Cell>,
        callback_value: BigUint,
        callback_payload: Option<ton_types::Cell>,
        attached_amount: u64,
    ) -> Result<InternalMessage> {
        let mut builder = BuilderData::new();

        // Opcode
        builder.append_u32(JETTON_TRANSFER_OPCODE)?;

        // Query id
        builder.append_u64(self.clock.now_ms_u64())?;

        // Amount
        let grams =
            ton_block::Grams::new(amount.to_u128().ok_or(JettonWalletError::TryFromGrams)?)?;
        grams.write_to(&mut builder)?;

        // Recipient
        destination.write_to(&mut builder)?;

        // Response destination
        remaining_gas_to.write_to(&mut builder)?;

        // Optional(TvmCell)
        match custom_payload {
            Some(payload) => {
                builder.append_bit_one()?;
                builder.checked_append_reference(payload)?;
            }
            None => {
                builder.append_bit_zero()?;
            }
        }

        // Callback value
        let grams = ton_block::Grams::new(
            callback_value
                .to_u128()
                .ok_or(JettonWalletError::TryFromGrams)?,
        )?;
        grams.write_to(&mut builder)?;

        let callback_payload = callback_payload.unwrap_or_default();
        if callback_payload.bit_length() < builder.bits_free() {
            builder.append_bit_zero()?;

            let callback_builder = BuilderData::from_cell(&callback_payload);
            builder.append_builder(&callback_builder)?;
        } else {
            builder.append_bit_one()?;
            builder.checked_append_reference(callback_payload)?;
        }

        let body = builder.into_cell().map(SliceData::load_cell)??;

        Ok(InternalMessage {
            source: Some(self.owner.clone()),
            destination: self.address().clone(),
            amount: attached_amount,
            bounce: true,
            body,
        })
    }

    pub async fn refresh(&mut self) -> Result<()> {
        let mut balance = self.balance.clone();

        let handler = self.handler.as_ref();
        self.contract_subscription
            .refresh(
                &mut make_contract_state_handler(self.clock.clone(), &mut balance),
                &mut make_transactions_handler(handler),
                &mut |_, _| {},
                &mut |_| {},
            )
            .await?;

        if balance != self.balance {
            self.balance = balance;
            handler.on_balance_changed(self.balance.clone());
        }

        Ok(())
    }

    pub async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()> {
        let mut balance: BigInt = self.balance.clone().into();

        let handler = self.handler.as_ref();
        self.contract_subscription.handle_block(
            block,
            &mut |transactions, batch_info| {
                let transactions = transactions
                    .into_iter()
                    .filter_map(|transaction| {
                        let description = match transaction.data.description.read_struct().ok()? {
                            ton_block::TransactionDescr::Ordinary(description) => description,
                            _ => return None,
                        };

                        let data = parse_jetton_transaction(&transaction.data, &description);

                        if let Some(data) = &data {
                            match data {
                                JettonWalletTransaction::Transfer(transfer) => {
                                    balance -= transfer.tokens.clone().to_bigint().trust_me();
                                }
                                JettonWalletTransaction::InternalTransfer(transfer) => {
                                    balance += transfer.tokens.clone().to_bigint().trust_me();
                                }
                            }
                        }

                        let transaction =
                            Transaction::try_from((transaction.hash, transaction.data)).ok()?;

                        Some(TransactionWithData { transaction, data })
                    })
                    .collect();

                handler.on_transactions_found(transactions, batch_info)
            },
            &mut |_, _| {},
            &mut |_| {},
        )?;

        let balance = balance.to_biguint().unwrap_or_default();
        if balance != self.balance {
            self.balance = balance;
            handler.on_balance_changed(self.balance.clone());
        }

        Ok(())
    }

    pub async fn preload_transactions(&mut self, from_lt: u64) -> Result<()> {
        let handler = self.handler.as_ref();
        self.contract_subscription
            .preload_transactions(from_lt, &mut make_transactions_handler(handler))
            .await
    }
}

pub trait JettonWalletSubscriptionHandler: Send + Sync {
    fn on_balance_changed(&self, balance: BigUint);

    /// Called every time new transactions are detected.
    /// - When new block found
    /// - When manually requesting the latest transactions (can be called several times)
    /// - When preloading transactions
    fn on_transactions_found(
        &self,
        transactions: Vec<TransactionWithData<JettonWalletTransaction>>,
        batch_info: TransactionsBatchInfo,
    );
}

pub async fn get_token_wallet_details(
    clock: &dyn Clock,
    transport: &dyn Transport,
    token_wallet: &MsgAddressInt,
) -> Result<(JettonWalletData, JettonRootData)> {
    let mut token_wallet_state = match transport.get_contract_state(token_wallet).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(JettonWalletError::InvalidTokenWalletContract.into())
        }
    };

    nekoton_contracts::jetton::update_library_cell(&mut token_wallet_state.account.storage.state)?;

    let token_wallet_state =
        nekoton_contracts::jetton::TokenWalletContract(token_wallet_state.as_context(clock));

    let token_wallet_details = token_wallet_state.get_details()?;

    let root_contract_state = match transport
        .get_contract_state(&token_wallet_details.root_address)
        .await?
    {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(JettonWalletError::InvalidRootTokenContract.into())
        }
    };
    let root_contract_details =
        nekoton_contracts::jetton::RootTokenContract(root_contract_state.as_context(clock))
            .get_details()?;

    Ok((token_wallet_details, root_contract_details))
}

pub async fn get_token_root_details(
    clock: &dyn Clock,
    transport: &dyn Transport,
    root_token_contract: &MsgAddressInt,
) -> Result<JettonRootData> {
    let state = match transport.get_contract_state(root_token_contract).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(JettonWalletError::InvalidRootTokenContract.into())
        }
    };
    nekoton_contracts::jetton::RootTokenContract(state.as_context(clock)).get_details()
}

pub async fn get_token_root_details_from_token_wallet(
    clock: &dyn Clock,
    transport: &dyn Transport,
    token_wallet_address: &MsgAddressInt,
) -> Result<(MsgAddressInt, JettonRootData)> {
    let mut state = match transport.get_contract_state(token_wallet_address).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(JettonWalletError::WalletNotDeployed.into())
        }
    };

    nekoton_contracts::jetton::update_library_cell(&mut state.account.storage.state)?;

    let root_token_contract =
        nekoton_contracts::jetton::TokenWalletContract(state.as_context(clock)).root()?;

    let state = match transport.get_contract_state(&root_token_contract).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(JettonWalletError::InvalidRootTokenContract.into())
        }
    };
    let state = nekoton_contracts::jetton::RootTokenContract(state.as_context(clock));
    let details = state.get_details()?;

    Ok((root_token_contract, details))
}

fn make_contract_state_handler(
    clock: Arc<dyn Clock>,
    balance: &'_ mut BigUint,
) -> impl FnMut(&mut RawContractState) + '_ {
    move |contract_state| {
        if let RawContractState::Exists(state) = contract_state {
            nekoton_contracts::jetton::update_library_cell(&mut state.account.storage.state)
                .ok()
                .and_then(|_| {
                    nekoton_contracts::jetton::TokenWalletContract(state.as_context(clock.as_ref()))
                        .balance()
                        .ok()
                        .map(|new_balance| *balance = new_balance)
                });
        }
    }
}

fn make_transactions_handler(
    handler: &'_ dyn JettonWalletSubscriptionHandler,
) -> impl FnMut(Vec<RawTransaction>, TransactionsBatchInfo) + '_ {
    move |transactions, batch_info| {
        let transactions = transactions
            .into_iter()
            .filter_map(
                |transaction| match transaction.data.description.read_struct().ok()? {
                    ton_block::TransactionDescr::Ordinary(description) => {
                        let data = parse_jetton_transaction(&transaction.data, &description);

                        let transaction =
                            Transaction::try_from((transaction.hash, transaction.data)).ok()?;

                        Some(TransactionWithData { transaction, data })
                    }
                    _ => None,
                },
            )
            .collect();

        handler.on_transactions_found(transactions, batch_info)
    }
}

#[derive(thiserror::Error, Debug)]
enum JettonWalletError {
    #[error("Invalid root token contract")]
    InvalidRootTokenContract,
    #[error("Invalid token wallet contract")]
    InvalidTokenWalletContract,
    #[error("Wallet not deployed")]
    WalletNotDeployed,
    #[error("Failed to convert grams")]
    TryFromGrams,
    #[error("No source transaction produced")]
    NoSourceTx,
    #[error("No destination transaction produced")]
    NoDestTx,
    #[error("Source transaction failed with exit code {0:?}")]
    SourceTxFailed(Option<i32>),
    #[error("Destination transaction failed with exit code {0:?}")]
    DestinationTxFailed(Option<i32>),
}
