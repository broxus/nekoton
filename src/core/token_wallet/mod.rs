use std::convert::TryFrom;
use std::sync::Arc;

use anyhow::Result;
use num_bigint::{BigInt, BigUint, ToBigInt};
use ton_block::MsgAddressInt;

use nekoton_abi::*;
use nekoton_contracts::tip3_any::{RootTokenContractState, TokenWalletContractState};
use nekoton_contracts::{old_tip3, tip3_1};
use nekoton_utils::*;

use crate::core::models::*;
use crate::core::parsing::*;
use crate::core::transactions_tree::*;
use crate::transport::models::{RawContractState, RawTransaction};
use crate::transport::Transport;

use super::{ContractSubscription, InternalMessage};

pub struct TokenWallet {
    clock: Arc<dyn Clock>,
    contract_subscription: ContractSubscription,
    handler: Arc<dyn TokenWalletSubscriptionHandler>,
    owner: MsgAddressInt,
    symbol: Symbol,
    version: TokenWalletVersion,
    balance: BigUint,
}

impl TokenWallet {
    pub async fn subscribe(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        owner: MsgAddressInt,
        root_token_contract: MsgAddressInt,
        handler: Arc<dyn TokenWalletSubscriptionHandler>,
        preload_transactions: bool,
    ) -> Result<TokenWallet> {
        let state = match transport.get_contract_state(&root_token_contract).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists { .. } => {
                return Err(TokenWalletError::InvalidRootTokenContract.into())
            }
        };
        let state = RootTokenContractState(state.as_context(clock.as_ref()));
        let RootTokenContractDetails {
            symbol: name,
            decimals,
            version,
            name: full_name,
            ..
        } = state.guess_details()?;

        let address = state.get_wallet_address(version, &owner)?;
        let mut balance = Default::default();

        let contract_subscription = {
            let handler = handler.as_ref();

            // NOTE: create handler beforehead to prevent lifetime issues
            let mut on_transactions_found = match preload_transactions {
                true => Some(make_transactions_handler(handler, version)),
                false => None,
            };

            // Manual map is used here due to unsoundness
            // See issue: https://github.com/rust-lang/rust/issues/84305
            #[allow(trivial_casts)]
            #[allow(clippy::manual_map)]
            let on_transactions_found = match &mut on_transactions_found {
                Some(handler) => Some(handler as _),
                None => None,
            };

            ContractSubscription::subscribe(
                clock.clone(),
                transport,
                address,
                &mut make_contract_state_handler(clock.clone(), version, &mut balance),
                on_transactions_found,
            )
            .await?
        };

        handler.on_balance_changed(balance.clone());

        let symbol = Symbol {
            name,
            full_name,
            decimals,
            root_token_contract,
        };

        Ok(Self {
            clock,
            contract_subscription,
            handler,
            owner,
            symbol,
            version,
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

    pub fn symbol(&self) -> &Symbol {
        &self.symbol
    }

    pub fn version(&self) -> TokenWalletVersion {
        self.version
    }

    pub fn balance(&self) -> &BigUint {
        &self.balance
    }

    pub fn contract_state(&self) -> &ContractState {
        self.contract_subscription.contract_state()
    }

    pub async fn estimate_min_attached_amount(
        &self,
        destination: TransferRecipient,
        tokens: BigUint,
        notify_receiver: bool,
        payload: ton_types::Cell,
    ) -> Result<u64> {
        const FEE_MULTIPLIER: u128 = 2;

        // Prepare internal message
        let internal_message =
            self.prepare_transfer(destination, tokens, notify_receiver, payload, 0)?;

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

        type Err = fn(Option<i32>) -> TokenWalletError;
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
        let source_tx = tree.next().await?.ok_or(TokenWalletError::NoSourceTx)?;
        check_exit_code(&source_tx, TokenWalletError::SourceTxFailed)?;
        attached_amount += source_tx.total_fees.grams.as_u128();

        if source_tx.outmsg_cnt == 0 {
            return Err(TokenWalletError::NoDestTx.into());
        }

        if let Some(message) = tree.peek() {
            if message.state_init().is_some() && message.src_ref() == Some(self.address()) {
                // Simulate first deploy transaction
                // NOTE: we don't need to count attached amount here because of separate `initial_balance`
                let _ = tree.next().await?.ok_or(TokenWalletError::NoDestTx)?;
                //also we ignore non zero exit code for deploy transactions
            }
        }

        tree.retain_message_queue(|message| {
            message.state_init().is_none() && message.src_ref() == Some(self.address())
        });

        if tree.message_queue().len() != 1 {
            return Err(TokenWalletError::NoDestTx.into());
        }

        // Simulate destination transaction
        let dest_tx = tree.next().await?.ok_or(TokenWalletError::NoDestTx)?;
        check_exit_code(&dest_tx, TokenWalletError::DestinationTxFailed)?;
        attached_amount += dest_tx.total_fees.grams.as_u128();

        Ok((attached_amount * FEE_MULTIPLIER) as u64)
    }

    pub fn prepare_transfer(
        &self,
        destination: TransferRecipient,
        tokens: BigUint,
        notify_receiver: bool,
        payload: ton_types::Cell,
        mut attached_amount: u64,
    ) -> Result<InternalMessage> {
        if matches!(&destination, TransferRecipient::OwnerWallet(_)) {
            attached_amount += INITIAL_BALANCE;
        }

        let (function, input) = match self.version {
            TokenWalletVersion::OldTip3v4 => {
                use old_tip3::token_wallet_contract;
                match destination {
                    TransferRecipient::TokenWallet(token_wallet) => {
                        MessageBuilder::new(token_wallet_contract::transfer())
                            .arg(token_wallet) // to
                            .arg(BigUint128(tokens)) // tokens
                    }
                    TransferRecipient::OwnerWallet(owner_wallet) => {
                        MessageBuilder::new(token_wallet_contract::transfer_to_recipient())
                            .arg(BigUint256(Default::default())) // recipient_public_key
                            .arg(owner_wallet) // recipient_address
                            .arg(BigUint128(tokens)) // tokens
                            .arg(BigUint128(INITIAL_BALANCE.into())) // deploy_grams
                    }
                }
                .arg(BigUint128(Default::default())) // grams / transfer_grams
                .arg(&self.owner) // send_gas_to
                .arg(notify_receiver) // notify_receiver
                .arg(payload) // payload
                .build()
            }
            TokenWalletVersion::Tip3 => {
                use tip3_1::token_wallet_contract;
                match destination {
                    TransferRecipient::TokenWallet(token_wallet) => {
                        MessageBuilder::new(token_wallet_contract::transfer_to_wallet())
                            .arg(BigUint128(tokens)) // amount
                            .arg(token_wallet) // recipient token wallet
                    }
                    TransferRecipient::OwnerWallet(owner_wallet) => {
                        MessageBuilder::new(token_wallet_contract::transfer())
                            .arg(BigUint128(tokens)) // amount
                            .arg(owner_wallet) // recipient
                            .arg(BigUint128(INITIAL_BALANCE.into())) // deployWalletValue
                    }
                }
                .arg(&self.owner) // remainingGasTo
                .arg(notify_receiver) // notify
                .arg(payload) // payload
                .build()
            }
        };

        let body = function
            .encode_internal_input(&input)
            .and_then(ton_types::SliceData::load_builder)?;

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
                &mut make_contract_state_handler(self.clock.clone(), self.version, &mut balance),
                &mut make_transactions_handler(handler, self.version),
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
        let version = self.version;
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

                        let data =
                            parse_token_transaction(&transaction.data, &description, version);

                        if let Some(data) = &data {
                            match data {
                                TokenWalletTransaction::IncomingTransfer(
                                    TokenIncomingTransfer { tokens, .. },
                                )
                                | TokenWalletTransaction::Accept(tokens)
                                | TokenWalletTransaction::SwapBackBounced(tokens)
                                | TokenWalletTransaction::TransferBounced(tokens) => {
                                    balance += tokens.clone().to_bigint().trust_me();
                                }
                                TokenWalletTransaction::OutgoingTransfer(
                                    TokenOutgoingTransfer { tokens, .. },
                                )
                                | TokenWalletTransaction::SwapBack(TokenSwapBack {
                                    tokens, ..
                                }) => {
                                    balance -= tokens.clone().to_bigint().trust_me();
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
            .preload_transactions(
                from_lt,
                &mut make_transactions_handler(handler, self.version),
            )
            .await
    }
}

pub trait TokenWalletSubscriptionHandler: Send + Sync {
    fn on_balance_changed(&self, balance: BigUint);

    /// Called every time new transactions are detected.
    /// - When new block found
    /// - When manually requesting the latest transactions (can be called several times)
    /// - When preloading transactions
    fn on_transactions_found(
        &self,
        transactions: Vec<TransactionWithData<TokenWalletTransaction>>,
        batch_info: TransactionsBatchInfo,
    );
}

pub async fn get_token_root_details(
    clock: &dyn Clock,
    transport: &dyn Transport,
    root_token_contract: &MsgAddressInt,
) -> Result<RootTokenContractDetails> {
    let state = match transport.get_contract_state(root_token_contract).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(TokenWalletError::InvalidRootTokenContract.into())
        }
    };
    RootTokenContractState(state.as_context(clock)).guess_details()
}

pub async fn get_token_wallet_details(
    clock: &dyn Clock,
    transport: &dyn Transport,
    token_wallet: &MsgAddressInt,
) -> Result<(TokenWalletDetails, RootTokenContractDetails)> {
    let token_wallet_state = match transport.get_contract_state(token_wallet).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(TokenWalletError::InvalidTokenWalletContract.into())
        }
    };
    let token_wallet_state = TokenWalletContractState(token_wallet_state.as_context(clock));

    let version = token_wallet_state.get_version()?;
    let token_wallet_details = token_wallet_state.get_details(version)?;

    let root_contract_state = match transport
        .get_contract_state(&token_wallet_details.root_address)
        .await?
    {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(TokenWalletError::InvalidRootTokenContract.into())
        }
    };
    let root_contract_details =
        RootTokenContractState(root_contract_state.as_context(clock)).get_details(version)?;

    Ok((token_wallet_details, root_contract_details))
}

pub async fn get_token_root_details_from_token_wallet(
    clock: &dyn Clock,
    transport: &dyn Transport,
    token_wallet_address: &MsgAddressInt,
) -> Result<(MsgAddressInt, RootTokenContractDetails)> {
    let state = match transport.get_contract_state(token_wallet_address).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(TokenWalletError::WalletNotDeployed.into())
        }
    };
    let state = TokenWalletContractState(state.as_context(clock));
    let version = state.get_version()?;
    let root_token_contract = state.get_details(version)?.root_address;

    let state = match transport.get_contract_state(&root_token_contract).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(TokenWalletError::InvalidRootTokenContract.into())
        }
    };
    let state = RootTokenContractState(state.as_context(clock));
    let details = state.get_details(version)?;

    Ok((root_token_contract, details))
}

const INITIAL_BALANCE: u64 = 100_000_000; // 0.1 TON

fn make_contract_state_handler(
    clock: Arc<dyn Clock>,
    version: TokenWalletVersion,
    balance: &'_ mut BigUint,
) -> impl FnMut(&RawContractState) + '_ {
    move |contract_state| {
        if let RawContractState::Exists(state) = contract_state {
            if let Ok(new_balance) =
                TokenWalletContractState(state.as_context(clock.as_ref())).get_balance(version)
            {
                *balance = new_balance;
            }
        }
    }
}

fn make_transactions_handler(
    handler: &'_ dyn TokenWalletSubscriptionHandler,
    version: TokenWalletVersion,
) -> impl FnMut(Vec<RawTransaction>, TransactionsBatchInfo) + '_ {
    move |transactions, batch_info| {
        let transactions = transactions
            .into_iter()
            .filter_map(
                |transaction| match transaction.data.description.read_struct().ok()? {
                    ton_block::TransactionDescr::Ordinary(description) => {
                        let data =
                            parse_token_transaction(&transaction.data, &description, version);

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
enum TokenWalletError {
    #[error("Invalid root token contract")]
    InvalidRootTokenContract,
    #[error("Invalid token wallet contract")]
    InvalidTokenWalletContract,
    #[error("Wallet not deployed")]
    WalletNotDeployed,
    #[error("No source transaction produced")]
    NoSourceTx,
    #[error("No destination transaction produced")]
    NoDestTx,
    #[error("Source transaction failed with exit code {0:?}")]
    SourceTxFailed(Option<i32>),
    #[error("Destination transaction failed with exit code {0:?}")]
    DestinationTxFailed(Option<i32>),
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use ton_block::Deserializable;

    use nekoton_abi::LastTransactionId;

    use super::*;
    use crate::transport::models::ExistingContract;

    fn convert_address(addr: &str) -> MsgAddressInt {
        MsgAddressInt::from_str(addr).unwrap()
    }

    fn prepare_contract(data: &str) -> ExistingContract {
        let account = match ton_block::Account::construct_from_base64(data).unwrap() {
            ton_block::Account::Account(stuff) => stuff,
            ton_block::Account::AccountNone => unreachable!(),
        };
        ExistingContract {
            account,
            timings: Default::default(),
            last_transaction_id: LastTransactionId::Inexact { latest_lt: 0 },
        }
    }

    fn root_token_contract(version: TokenWalletVersion) -> ExistingContract {
        let data = match version {
            TokenWalletVersion::OldTip3v4 => ROOT_TOKEN_STATE_OLD_TIP3_V4,
            TokenWalletVersion::Tip3 => ROOT_TOKEN_STATE_TIP3,
        };
        prepare_contract(data)
    }

    const ROOT_TOKEN_STATE_OLD_TIP3_V4: &str = "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";
    const ROOT_TOKEN_STATE_TIP3: &str = "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";

    fn token_wallet_contract(version: TokenWalletVersion) -> ExistingContract {
        let data = match version {
            TokenWalletVersion::OldTip3v4 => TOKEN_WALLET_STATE_OLD_TIP3_V4,
            TokenWalletVersion::Tip3 => TOKEN_WALLET_STATE_TIP3,
        };
        prepare_contract(data)
    }

    const TOKEN_WALLET_STATE_OLD_TIP3_V4: &str = "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";
    const TOKEN_WALLET_STATE_TIP3: &str = "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";

    #[test]
    fn get_token_wallet_balance() {
        let versions = [TokenWalletVersion::OldTip3v4, TokenWalletVersion::Tip3];

        for &version in &versions {
            let contract = token_wallet_contract(version);
            let state = TokenWalletContractState(contract.as_context(&SimpleClock));

            let parsed_version = state.get_version().unwrap();
            assert_eq!(parsed_version, version);

            state.get_details(parsed_version).unwrap();
            state.get_balance(version).unwrap();
        }
    }

    #[test]
    fn compute_token_wallet_address() {
        let owner_address = "0:a921453472366b7feeec15323a96b5dcf17197c88dc0d4578dfa52900b8a33cb";

        // pairs of token version and token wallet address
        let versions = [
            (
                TokenWalletVersion::OldTip3v4,
                "0:e4eb5f354e5f0335f38a73b6dc9808c67d611a717b5ed184d6210fb3e73067ee",
            ),
            (
                TokenWalletVersion::Tip3,
                "0:a3d6926fc25c9ac9a93b1f0afab9dabe63798290ccdc318c1940b99b1c1dade6",
            ),
        ];

        // guess details from state for each version
        for &(version, token_wallet) in &versions {
            let contract = root_token_contract(version);
            let state = RootTokenContractState(contract.as_context(&SimpleClock));

            let details = state.guess_details().unwrap();
            assert_eq!(details.version, version);

            let address = state
                .get_wallet_address(details.version, &convert_address(owner_address))
                .unwrap();

            assert_eq!(address, convert_address(token_wallet));
        }
    }

    #[test]
    fn get_root_contract_details() {
        // Old
        let root_state = root_token_contract(TokenWalletVersion::OldTip3v4);
        let details = RootTokenContractState(root_state.as_context(&SimpleClock))
            .guess_details()
            .unwrap();
        assert_eq!(
            details.total_supply,
            BigUint::from_str("22000000000").unwrap()
        );
        assert_eq!(details.decimals, 9);
        assert_eq!(details.version, TokenWalletVersion::OldTip3v4);
        assert_eq!(details.symbol, "WTON");

        // New
        let root_state = root_token_contract(TokenWalletVersion::Tip3);
        let details = RootTokenContractState(root_state.as_context(&SimpleClock))
            .guess_details()
            .unwrap();
        assert_eq!(
            details.total_supply,
            BigUint::from_str("555666777000000000").unwrap()
        );
        assert_eq!(details.decimals, 9);
        assert_eq!(details.version, TokenWalletVersion::Tip3);
        assert_eq!(details.symbol, "TST1");
    }

    #[test]
    fn get_strange_root_contract_details() {
        let root_state = r#"{"account":"te6ccgECpgEALrQAAnKAHh5eeOtBZE9N4jZNP+Kf124tRZChZNcAVHqtbpKGWoYGmYCwsgYPfoTgAAB4cmmGFjKAl0UXiSZgAQTzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwe+zxf4AAAAAAAAAAAAONfmkrtgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBfUVECAhD0pCCK7VP0oANhAgEgBwQBAv8FAv5/jQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE+Gkh2zzTAAGOHYECANcYIPkBAdMAAZTT/wMBkwL4QuIg+GX5EPKoldMAAfJ64tM/AY4d+EMhuSCfMCD4I4ED6KiCCBt3QKC53pMg+GPg8jTYMNMfAfgjvPK5EQYCFtMfAds8+EdujoDeCggDbt9wItDTA/pAMPhpqTgA+ER/b3GCCJiWgG9ybW9zcG90+GSOgOAhxwDcIdMfId0B2zz4R26OgN5ICggBBlvbPAkCDvhBbuMA2zxQSQRYIIIQDC/yDbuOgOAgghApxIl+u46A4CCCEEvxYOK7joDgIIIQebJe4buOgOA8KBQLBFAgghBotV8/uuMCIIIQce7odbrjAiCCEHVszfe64wIgghB5sl7huuMCEA8ODALqMPhBbuMA0x/4RFhvdfhk0fhEcG9ycG9xgEBvdPhk+Er4TPhN+E74UPhR+FJvByHA/45CI9DTAfpAMDHIz4cgzoBgz0DPgc+DyM+T5sl7hiJvJ1UGJ88WJs8L/yXPFiTPC3/IJM8WI88WIs8KAGxyzc3JcPsAUA0Bvo5W+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPg8j4RG8VzwsfIm8nVQYnzxYmzwv/Jc8WJM8Lf8gkzxYjzxYizwoAbHLNzcn4RG8U+wDiMOMAf/hnSQPiMPhBbuMA0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZPhN+kJvE9cL/8MAjoCS+ADibfhv+E36Qm8T1wv/jhX4ScjPhYjOgG3PQM+Bz4HJgQCA+wDe2zx/+GdQRUkCsDD4QW7jAPpBldTR0PpA39cMAJXU0dDSAN/R+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8uBk+AAh+HAg+HJb2zx/+GdQSQLiMPhBbuMA+Ebyc3H4ZtH4TPhCuiCOFDD4TfpCbxPXC//AACCVMPhMwADf3vLgZPgAf/hy+E36Qm8T1wv/ji34TcjPhYjOjQPInEAAAAAAAAAAAAAAAAABzxbPgc+Bz5EhTuze+ErPFslx+wDe2zx/+GcRSQGS7UTQINdJwgGOPNP/0z/TANX6QPpA+HH4cPht+kDU0//Tf/QEASBuldDTf28C3/hv1woA+HL4bvhs+Gv4an/4Yfhm+GP4Yo6A4hIB/vQFcSGAQPQOjiSNCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATf+GpyIYBA9A+SyMnf+GtzIYBA9A6T1wv/kXDi+Gx0IYBA9A6OJI0IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABN/4bXD4bm0TAM74b40IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPhwjQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE+HFw+HJwAYBA9A7yvdcL//hicPhjcPhmf/hhA0AgghA/ENGru46A4CCCEElpWH+7joDgIIIQS/Fg4rrjAiAZFQL+MPhBbuMA+kGV1NHQ+kDf1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/XDACV1NHQ0gDf1NH4TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y4GQkwgDy4GQk+E678uBlJfpCbxPXC//DAFAWAjLy4G8l+CjHBbPy4G/4TfpCbxPXC//DAI6AGBcB5I5o+CdvECS88uBuI4IK+vCAvPLgbvgAJPhOAaG1f/huIyZ/yM+FgMoAc89AzgH6AoBpz0DPgc+DyM+QY0hcCibPC3/4TM8L//hNzxYk+kJvE9cL/8MAkSSS+CjizxYjzwoAIs8Uzclx+wDiXwbbPH/4Z0kB7oIK+vCA+CdvENs8obV/tgn4J28QIYIK+vCAoLV/vPLgbiBy+wIl+E4BobV/+G4mf8jPhYDKAHPPQM6Abc9Az4HPg8jPkGNIXAonzwt/+EzPC//4Tc8WJfpCbxPXC//DAJElkvhN4s8WJM8KACPPFM3JgQCB+wAwmwIoIIIQP1Z5UbrjAiCCEElpWH+64wIcGgKQMPhBbuMA0x/4RFhvdfhk0fhEcG9ycG9xgEBvdPhk+E4hwP+OIyPQ0wH6QDAxyM+HIM6AYM9Az4HPgc+TJaVh/iHPC3/JcPsAUBsBgI43+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPgfhEbxXPCx8hzwt/yfhEbxT7AOIw4wB/+GdJBPww+EFu4wD6QZXU0dD6QN/XDX+V1NHQ03/f+kGV1NHQ+kDf1wwAldTR0NIA39TR+E9us/Lga/hJ+E8gbvJ/bxHHBfLgbCP4TyBu8n9vELvy4G0j+E678uBlI8IA8uBkJPgoxwWz8uBv+E36Qm8T1wv/wwCOgI6A4iP4TgGhtX9QHx4dAbT4bvhPIG7yf28QJKG1f/hPIG7yf28RbwL4byR/yM+FgMoAc89AzoBtz0DPgc+DyM+QY0hcCiXPC3/4TM8L//hNzxYkzxYjzwoAIs8UzcmBAIH7AF8F2zx/+GdJAi7bPIIK+vCAvPLgbvgnbxDbPKG1f3L7ApubAnKCCvrwgPgnbxDbPKG1f7YJ+CdvECGCCvrwgKC1f7zy4G4gcvsCggr68ID4J28Q2zyhtX+2CXL7AjCbmwIoIIIQLalNL7rjAiCCED8Q0au64wInIQL+MPhBbuMA1w3/ldTR0NP/3/pBldTR0PpA39cNf5XU0dDTf9/XDX+V1NHQ03/f1w1/ldTR0NN/3/pBldTR0PpA39cMAJXU0dDSAN/U0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZCXCAFAiAvzy4GQl+E678uBlJvpCbxPXC//AACCUMCfAAN/y4G/4TfpCbxPXC//DAI6AjiD4J28QJSWgtX+88uBuI4IK+vCAvPLgbif4TL3y4GT4AOJtKMjL/3BYgED0Q/hKcViAQPQW+EtyWIBA9BcoyMv/c1iAQPRDJ3RYgED0Fsj0AMkmIwH8+EvIz4SA9AD0AM+ByY0IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCbCAI43ISD5APgo+kJvEsjPhkDKB8v/ydAoIcjPhYjOAfoCgGnPQM+Dz4MizxTPgc+RotV8/slx+wAxMZ0h+QDIz4oAQMv/ydAx4vhNJAG4+kJvE9cL/8MAjlEn+E4BobV/+G4gf8jPhYDKAHPPQM6Abc9Az4HPg8jPkGNIXAopzwt/+EzPC//4Tc8WJvpCbxPXC//DAJEmkvhN4s8WJc8KACTPFM3JgQCB+wAlAbyOUyf4TgGhtX/4biUhf8jPhYDKAHPPQM4B+gKAac9Az4HPg8jPkGNIXAopzwt/+EzPC//4Tc8WJvpCbxPXC//DAJEmkvgo4s8WJc8KACTPFM3JcfsA4ltfCNs8f/hnSQFmggr68ID4J28Q2zyhtX+2CfgnbxAhggr68ICgtX8noLV/vPLgbif4TccFs/LgbyBy+wIwmwHoMNMf+ERYb3X4ZNF0IcD/jiMj0NMB+kAwMcjPhyDOgGDPQM+Bz4HPkralNL4hzwsfyXD7AI43+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPgfhEbxXPCx8hzwsfyfhEbxT7AOIw4wB/+GdJA0AgghAQR8kEu46A4CCCEBjSFwK7joDgIIIQKcSJfrrjAjQsKQL+MPhBbuMA+kGV1NHQ+kDf+kGV1NHQ+kDf1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/XDACV1NHQ0gDf1NH4TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y4GQl+kJvE9cL/8MA8uBvJFAqAvbCAPLgZCYmxwWz8uBv+E36Qm8T1wv/wwCOgI5X+CdvECS88uBuI4IK+vCAcqi1f7zy4G74ACMnyM+FiM4B+gKAac9Az4HPg8jPkP1Z5UYnzxYmzwt/JPpCbxPXC//DAJEkkvgo4s8WI88KACLPFM3JcfsA4l8H2zx/+GcrSQHMggr68ID4J28Q2zyhtX+2CfgnbxAhggr68IByqLV/oLV/vPLgbiBy+wInyM+FiM6Abc9Az4HPg8jPkP1Z5UYozxYnzwt/JfpCbxPXC//DAJElkvhN4s8WJM8KACPPFM3JgQCB+wAwmwIoIIIQGG1zvLrjAiCCEBjSFwK64wIyLQL+MPhBbuMA1w1/ldTR0NN/39cN/5XU0dDT/9/6QZXU0dD6QN/6QZXU0dD6QN/XDACV1NHQ0gDf1NEh+FKxIJww+FD6Qm8T1wv/wADf8uBwJCRtIsjL/3BYgED0Q/hKcViAQPQW+EtyWIBA9BciyMv/c1iAQPRDIXRYgED0Fsj0AFAuA77J+EvIz4SA9AD0AM+BySD5AMjPigBAy//J0DFsIfhJIccF8uBnJPhNxwWzIJUwJfhMvd/y4G/4TfpCbxPXC//DAI6AjoDiJvhOAaC1f/huIiCcMPhQ+kJvE9cL/8MA3jEwLwHIjkP4UMjPhYjOgG3PQM+Bz4PIz5FlBH7m+CjPFvhKzxYozwt/J88L/8gnzxb4Sc8WJs8WyPhOzwt/Jc8Uzc3NyYEAgPsAjhQjyM+FiM6Abc9Az4HPgcmBAID7AOIwXwbbPH/4Z0kBGPgnbxDbPKG1f3L7ApsBPIIK+vCA+CdvENs8obV/tgn4J28QIbzy4G4gcvsCMJsCrDD4QW7jANMf+ERYb3X4ZNH4RHBvcnBvcYBAb3T4ZPhPbrOW+E8gbvJ/jidwjQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEbwLiIcD/UDMB7o4sI9DTAfpAMDHIz4cgzoBgz0DPgc+Bz5Jhtc7yIW8iWCLPC38hzxZsIclw+wCOQPhEIG8TIW8S+ElVAm8RyHLPQMoAc89AzgH6AvQAgGjPQM+Bz4H4RG8VzwsfIW8iWCLPC38hzxZsIcn4RG8U+wDiMOMAf/hnSQIoIIIQDwJYqrrjAiCCEBBHyQS64wI6NQP2MPhBbuMA1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/6QZXU0dD6QN/U0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZCTCAPLgZCT4Trvy4GX4TfpCbxPXC//DACCOgN4gUDk2AmCOHTD4TfpCbxPXC//AACCeMCP4J28QuyCUMCPCAN7e3/LgbvhN+kJvE9cL/8MAjoA4NwHCjlf4ACT4TgGhtX/4biP4Sn/Iz4WAygBzz0DOAfoCgGnPQM+Bz4PIz5C4oiKqJs8Lf/hMzwv/+E3PFiT6Qm8T1wv/wwCRJJL4KOLPFsgkzxYjzxTNzclw+wDiXwXbPH/4Z0kBzIIK+vCA+CdvENs8obV/tgly+wIk+E4BobV/+G74Sn/Iz4WAygBzz0DOgG3PQM+Bz4PIz5C4oiKqJs8Lf/hMzwv/+E3PFiT6Qm8T1wv/wwCRJJL4TeLPFsgkzxYjzxTNzcmBAID7AJsBCjDbPMIAmwMuMPhBbuMA+kGV1NHQ+kDf0ds82zx/+GdQO0kAvPhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZPhOwADy4GT4ACDIz4UIzo0DyA+gAAAAAAAAAAAAAAAAAc8Wz4HPgcmBAKD7ADADPiCCCyHRc7uOgOAgghALP89Xu46A4CCCEAwv8g264wJCPz0D/jD4QW7jANcNf5XU0dDTf9/6QZXU0dD6QN/6QZXU0dD6QN/U0fhK+EnHBfLgZiPCAPLgZCP4Trvy4GX4J28Q2zyhtX9y+wIj+E4BobV/+G74Sn/Iz4WAygBzz0DOgG3PQM+Bz4PIz5C4oiKqJc8Lf/hMzwv/+E3PFiTPFsgkzxZQmz4BJCPPFM3NyYEAgPsAXwTbPH/4Z0kCKCCCEAXFAA+64wIgghALP89XuuMCQUACVjD4QW7jANcNf5XU0dDTf9/R+Er4SccF8uBm+AAg+E4BoLV/+G4w2zx/+GdQSQKWMPhBbuMA+kGV1NHQ+kDf0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZPgAIPhxMNs8f/hnUEkCJCCCCXwzWbrjAiCCCyHRc7rjAkZDA/Aw+EFu4wD6QZXU0dD6QN/XDX+V1NHQ03/f1w1/ldTR0NN/39H4TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y4GQhwAAgljD4T26zs9/y4Gr4TfpCbxPXC//DAI6AkvgA4vhPbrNQRUQBiI4S+E8gbvJ/bxAiupYgI28C+G/eliAjbwL4b+L4TfpCbxPXC/+OFfhJyM+FiM6Abc9Az4HPgcmBAID7AN5fA9s8f/hnSQEmggr68ID4J28Q2zyhtX+2CXL7ApsC/jD4QW7jANMf+ERYb3X4ZNH4RHBvcnBvcYBAb3T4ZPhLIcD/jiIj0NMB+kAwMcjPhyDOgGDPQM+Bz4HPkgXwzWYhzxTJcPsAjjb4RCBvEyFvEvhJVQJvEchyz0DKAHPPQM4B+gL0AIBoz0DPgc+B+ERvFc8LHyHPFMn4RG8U+wBQRwEO4jDjAH/4Z0kEQCHWHzH4QW7jAPgAINMfMiCCEBjSFwK6joCOgOIwMNs8UExKSQCs+ELIy//4Q88LP/hGzwsAyPhN+FD4UV4gzs7O+Er4S/hM+E74T/hSXmDPEc7My//LfwEgbrOOFcgBbyLIIs8LfyHPFmwhzxcBz4PPEZMwz4HiygDJ7VQBFiCCEC4oiKq6joDeSwEwIdN/M/hOAaC1f/hu+E36Qm8T1wv/joDeTgI8IdN/MyD4TgGgtX/4bvhR+kJvE9cL/8MAjoCOgOIwT00BGPhN+kJvE9cL/46A3k4BUIIK+vCA+CdvENs8obV/tgly+wL4TcjPhYjOgG3PQM+Bz4HJgQCA+wCbAYD4J28Q2zyhtX9y+wL4UcjPhYjOgG3PQM+Bz4PIz5DqFdlC+CjPFvhKzxYizwt/yPhJzxb4Ts8Lf83NyYEAgPsAmwB+7UTQ0//TP9MA1fpA+kD4cfhw+G36QNTT/9N/9AQBIG6V0NN/bwLf+G/XCgD4cvhu+Gz4a/hqf/hh+Gb4Y/hiAf6qTG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gTWF1cmlzIGV0IGR1aSBlZ2V0IG5pYmggdGVtcHVzIHB1bHZpbmFyLiBRdWlzcXVlIHVsbGFtY29ycGVyLCBkb2xvciBzUgH+ZWQgdm9sdXRwYXQgdm9sdXRwYXQsIGV4IG1hdXJpcyBwb3N1ZXJlIGV4LCBldSB1bHRyaWNpZXMgZGlhbSBuZXF1ZSBtb2xlc3RpZSBtaS4gTWFlY2VuYXMgYSBibGFuZGl0IG1hc3NhLiBGdXNjZSBhdCB2ZWxpdCB0b3J0b1MB/nIuIExvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQuIEFlbmVhbiBzY2VsZXJpc3F1ZSBkaWN0dW0gcmlzdXMgcXVpcyBoZW5kcmVyaXQuIER1aXMgaW50ZXJkdW0gZWxlaWZUAf5lbmQgZW5pbS4gRnVzY2UgdmVsIGZlbGlzIGNvbW1vZG8sIGZlcm1lbnR1bSB2ZWxpdCBzdXNjaXBpdCwgaW1wZXJkaWV0IGxlby4gTWFlY2VuYXMgdml0YWUgcHVydXMgdml0YWUgbWV0dXMgbWFsZXN1YWRhIGZldWdpYXQuVQH+IFZlc3RpYnVsdW0gYW50ZSBpcHN1bSBwcmltaXMgaW4gZmF1Y2lidXMgb3JjaSBsdWN0dXMgZXQgdWx0cmljZXMgcG9zdWVyZSBjdWJpbGlhIGN1cmFlOyBWZXN0aWJ1bHVtIHNlZCBkaWFtIHZpdGFlIGxhY3VzIG1vbGVzdFYB/mllIHZhcml1cyBldSBhdCBlcmF0LiBOdWxsYSBsdWN0dXMgcGVsbGVudGVzcXVlIG5pYmggdmVsIHNvZGFsZXMuIFZlc3RpYnVsdW0gYW50ZSBvcmNpLCBwbGFjZXJhdCBhYyBydXRydW0gZWdldCwgYmliZW5kdW0gaW4gYW5XAf50ZS4gTWF1cmlzIG1hdHRpcyBtYXNzYSBldCB0b3J0b3IgbW9sbGlzIGZpbmlidXMuqlBoYXNlbGx1cyBiaWJlbmR1bSBsaWd1bGEgdG9ydG9yLCBpZCB2ZWhpY3VsYSBhcmN1IGNvbnNlcXVhdCBlbGVtZW50dW0uIEFsaXF1WAH+YW0gdnVscHV0YXRlIGhlbmRyZXJpdCBhcmN1IGlkIGZldWdpYXQuIEV0aWFtIGNvbW1vZG8gbG9ib3J0aXMgZWdlc3Rhcy4gSW4gYSBudWxsYSB0ZW1wb3IsIGZyaW5naWxsYSBkdWkgZXUsIGxvYm9ydGlzIHVybmEuIE1hZVkB/mNlbmFzIG9ybmFyZSwgbWkgYWMgdml2ZXJyYSBhdWN0b3IsIGV4IHNlbSBzb2RhbGVzIG9yY2ksIHF1aXMgcnV0cnVtIG1pIHZlbGl0IGEgbmliaC4gRHVpcyBpYWN1bGlzLCBzZW0gZ3JhdmlkYSBpbXBlcmRpZXQgY29uZGlaAf5tZW50dW0sIGlwc3VtIGRpYW0gdWxsYW1jb3JwZXIgZHVpLCBhdCBlbGVtZW50dW0gc2VtIHB1cnVzIHNlZCBhcmN1LiBEb25lYyB2ZWwgb3JuYXJlIG1hZ25hLiBDdXJhYml0dXIgY29uc2VjdGV0dXIgbmVjIG1hZ25hIGF0WwH+IHVsdHJpY2VzLiBJbnRlZ2VyIG5lYyBmaW5pYnVzIHRlbGx1cy4gSW50ZWdlciB2aXRhZSBtYXR0aXMgZHVpLCB2aXRhZSB0cmlzdGlxdWUgbWkuIFNlZCBuaWJoIG9yY2ksIGVsZW1lbnR1bSBub24gbmlzaSBhYywgZmFjaVwB/mxpc2lz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","timings":{"genLt":"16558098000001","genUtime":1626868952},"lastTransactionId":{"isExact":true,"lt":"16554099000005","hash":"a73789af4437ff5a58f33a5b29a347d01b6b99088009437b8e47d73751f51741"}}"#;
        let root_state: ExistingContract = serde_json::from_str(root_state).unwrap();
        let root_state = RootTokenContractState(root_state.as_context(&SimpleClock));
        root_state.guess_details().unwrap();
    }
}
