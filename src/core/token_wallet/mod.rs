use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

use anyhow::Result;
use num_bigint::{BigInt, BigUint, ToBigInt};
use ton_block::MsgAddressInt;

use nekoton_abi::*;
use nekoton_utils::*;

use crate::core::models::*;
use crate::core::parsing::*;
use crate::transport::models::{ExistingContract, RawContractState, RawTransaction};
use crate::transport::Transport;

use super::{ContractSubscription, InternalMessage};

use self::models::*;

mod models;

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
    ) -> Result<TokenWallet> {
        let state = match transport.get_contract_state(&root_token_contract).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists => {
                return Err(TokenWalletError::InvalidRootTokenContract.into())
            }
        };
        let state = RootTokenContractState(&state);
        let RootTokenContractDetails {
            symbol: name,
            decimals,
            version,
            name: full_name,
            ..
        } = state.guess_details(clock.as_ref())?;

        let address = state.get_wallet_address(clock.as_ref(), version, &owner, None)?;

        let mut balance = Default::default();
        let contract_subscription = ContractSubscription::subscribe(
            clock.clone(),
            transport,
            address,
            make_contract_state_handler(clock.clone(), version, &mut balance),
            make_transactions_handler(&handler, version),
        )
        .await?;

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

    pub fn prepare_deploy(&self) -> Result<InternalMessage> {
        const ATTACHED_AMOUNT: u64 = 500_000_000; // 0.5 TON

        let (function, input) = MessageBuilder::new(
            nekoton_contracts::abi::root_token_contract_v4(),
            "deployEmptyWallet",
        )
        .trust_me()
        .arg(BigUint128(INITIAL_BALANCE.into()))
        .arg(BigUint256(Default::default()))
        .arg(&self.owner)
        .arg(&self.owner)
        .build();

        let body = function
            .encode_input(&Default::default(), &input, true, None)?
            .into();

        Ok(InternalMessage {
            source: Some(self.owner.clone()),
            destination: self.symbol.root_token_contract.clone(),
            amount: ATTACHED_AMOUNT,
            bounce: true,
            body,
        })
    }

    pub fn prepare_transfer(
        &self,
        destination: TransferRecipient,
        tokens: BigUint,
        notify_receiver: bool,
        payload: ton_types::Cell,
    ) -> Result<InternalMessage> {
        const ATTACHED_AMOUNT: u64 = 500_000_000; // 0.5 TON

        let contract = select_token_contract(self.version)?;

        let (function, input) = match destination {
            TransferRecipient::TokenWallet(token_wallet) => {
                MessageBuilder::new(contract, "transfer")
                    .trust_me()
                    .arg(token_wallet) // to
                    .arg(BigUint128(tokens)) // tokens
            }
            TransferRecipient::OwnerWallet(owner_wallet) => {
                MessageBuilder::new(contract, "transferToRecipient")
                    .trust_me()
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
        .build();

        let body = function
            .encode_input(&Default::default(), &input, true, None)?
            .into();

        Ok(InternalMessage {
            source: Some(self.owner.clone()),
            destination: self.address().clone(),
            amount: ATTACHED_AMOUNT,
            bounce: true,
            body,
        })
    }

    pub fn prepare_swap_back(
        &self,
        destination: String,
        tokens: BigUint,
        proxy_address: MsgAddressInt,
    ) -> Result<InternalMessage> {
        const ATTACHED_AMOUNT: u64 = 500_000_000; // 0.5 TON

        let destination = hex::decode(destination.trim_start_matches("0x"))
            .ok()
            .and_then(|data| if data.len() == 20 { Some(data) } else { None })
            .ok_or(TokenWalletError::InvalidSwapBackDestination)?;

        let callback_payload = match destination
            .token_value()
            .write_to_cells(&ton_abi::contract::ABI_VERSION_2_0)
        {
            Ok(cells) if cells.len() == 1 && cells[0].data.references().len() == 1 => {
                cells[0].data.references()[0].clone()
            }
            _ => return Err(TokenWalletError::InvalidSwapBackDestination.into()),
        };

        let contract = select_token_contract(self.version)?;

        let (function, input) = MessageBuilder::new(contract, "burnByOwner")
            .trust_me()
            .arg(BigUint128(tokens)) // tokens
            .arg(BigUint128(Default::default())) // grams
            .arg(&self.owner) // send_gas_to
            .arg(proxy_address) // callback_address
            .arg(callback_payload) // callback_payload
            .build();

        let body = function
            .encode_input(&Default::default(), &input, true, None)?
            .into();

        Ok(InternalMessage {
            source: Some(self.owner.clone()),
            destination: self.address().clone(),
            amount: ATTACHED_AMOUNT,
            bounce: true,
            body,
        })
    }

    pub async fn refresh(&mut self) -> Result<()> {
        let mut balance = self.balance.clone();

        self.contract_subscription
            .refresh(
                make_contract_state_handler(self.clock.clone(), self.version, &mut balance),
                make_transactions_handler(&self.handler, self.version),
                |_, _| {},
                |_| {},
            )
            .await?;

        if balance != self.balance {
            self.balance = balance;
            self.handler.on_balance_changed(self.balance.clone());
        }

        Ok(())
    }

    pub async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()> {
        let version = self.version;
        let mut balance: BigInt = self.balance.clone().into();

        let handler = &self.handler;
        self.contract_subscription.handle_block(
            block,
            |transactions, batch_info| {
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

                handler
                    .as_ref()
                    .on_transactions_found(transactions, batch_info)
            },
            |_, _| {},
            |_| {},
        )?;

        let balance = balance.to_biguint().unwrap_or_default();
        if balance != self.balance {
            self.balance = balance;
            self.handler.on_balance_changed(self.balance.clone());
        }

        Ok(())
    }

    pub async fn preload_transactions(&mut self, from: TransactionId) -> Result<()> {
        self.contract_subscription
            .preload_transactions(from, make_transactions_handler(&self.handler, self.version))
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
        RawContractState::NotExists => {
            return Err(TokenWalletError::InvalidRootTokenContract.into())
        }
    };
    RootTokenContractState(&state).guess_details(clock)
}

pub async fn get_token_root_details_from_token_wallet(
    clock: &dyn Clock,
    transport: &dyn Transport,
    token_wallet_address: &MsgAddressInt,
) -> Result<(MsgAddressInt, RootTokenContractDetails)> {
    let state = match transport.get_contract_state(token_wallet_address).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists => return Err(TokenWalletError::WalletNotDeployed.into()),
    };
    let state = TokenWalletContractState(&state);
    let version = state.get_version(clock)?;
    let root_token_contract = state.get_details(clock, version)?.root_address;

    let state = match transport.get_contract_state(&root_token_contract).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists => {
            return Err(TokenWalletError::InvalidRootTokenContract.into())
        }
    };
    let state = RootTokenContractState(&state);
    let details = state.get_details(clock, version)?;

    Ok((root_token_contract, details))
}

fn select_token_contract(version: TokenWalletVersion) -> Result<&'static ton_abi::Contract> {
    Ok(match version {
        TokenWalletVersion::OldTip3v4 => nekoton_contracts::abi::ton_token_wallet_v4(),
    })
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
                TokenWalletContractState(state).get_balance(clock.as_ref(), version)
            {
                *balance = new_balance;
            }
        }
    }
}

fn make_transactions_handler<T>(
    handler: &'_ T,
    version: TokenWalletVersion,
) -> impl FnMut(Vec<RawTransaction>, TransactionsBatchInfo) + '_
where
    T: AsRef<dyn TokenWalletSubscriptionHandler>,
{
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

        handler
            .as_ref()
            .on_transactions_found(transactions, batch_info)
    }
}

pub struct RootTokenContractState<'a>(pub &'a ExistingContract);

impl RootTokenContractState<'_> {
    /// Calculates token wallet address
    pub fn get_wallet_address(
        &self,
        clock: &dyn Clock,
        version: TokenWalletVersion,
        owner: &MsgAddressInt,
        wallet_public_key: Option<&[u8]>,
    ) -> Result<MsgAddressInt> {
        let wallet_public_key = match wallet_public_key {
            Some(a) => {
                anyhow::ensure!(a.len() == 32, "Bad len for pubkey: {}", a.len());
                BigUint::from_bytes_be(a)
            }
            None => BigUint::default(),
        };
        let mut function = FunctionBuilder::new("getWalletAddress")
            .default_headers()
            .input("wallet_public_key_", ton_abi::ParamType::Uint(256))
            .input("owner_address_", ton_abi::ParamType::Address)
            .output("address", ton_abi::ParamType::Address);

        let mut inputs = adjust_responsible(&mut function, version);
        inputs.push(ton_abi::Token::new(
            "wallet_public_key_",
            BigUint256(wallet_public_key).token_value(),
        ));
        inputs.push(ton_abi::Token::new("owner_address_", owner.token_value()));

        let address = self
            .0
            .run_local(clock, &function.build(), &inputs)?
            .unpack_first()?;

        Ok(address)
    }

    /// Tries to guess version and retrieve details
    pub fn guess_details(&self, clock: &dyn Clock) -> Result<RootTokenContractDetails> {
        // check Tip3v3+ version via direct call
        match get_version_direct(clock, self.0) {
            Ok(GotVersion::Known(version)) => return self.get_details(clock, version),
            Ok(GotVersion::Unknown) => return Err(TokenWalletError::UnknownVersion.into()),
            _ => {} // fallback to Tip3v1 or Tip3v2
        };

        Err(TokenWalletError::UnknownVersion.into())
    }

    /// Retrieve details using specified version
    pub fn get_details(
        &self,
        clock: &dyn Clock,
        version: TokenWalletVersion,
    ) -> Result<RootTokenContractDetails> {
        let details_abi = TupleBuilder::new()
            .item("name", ton_abi::ParamType::Bytes)
            .item("symbol", ton_abi::ParamType::Bytes)
            .item("decimals", ton_abi::ParamType::Uint(8))
            .item("root_public_key", ton_abi::ParamType::Uint(256))
            .item("root_owner_address", ton_abi::ParamType::Address)
            .item("total_supply", ton_abi::ParamType::Uint(128));

        let mut function = FunctionBuilder::new("getDetails")
            .default_headers()
            .output("value0", details_abi.build());

        let inputs = adjust_responsible(&mut function, version);
        let outputs = self.0.run_local(clock, &function.build(), &inputs)?;

        Ok(unpack_brief_root_token_contract_details(version, outputs)?)
    }
}

fn unpack_brief_root_token_contract_details(
    version: TokenWalletVersion,
    tokens: Vec<ton_abi::Token>,
) -> UnpackerResult<RootTokenContractDetails> {
    let data: BriefRootTokenContractDetails = tokens.unpack_first()?;
    Ok(RootTokenContractDetails {
        version,
        name: data.name,
        symbol: data.symbol,
        decimals: data.decimals,
        owner_address: data.root_owner_address,
        total_supply: data.total_supply,
        root_public_key: data.root_public_key,
    })
}

#[derive(Debug)]
pub struct TokenWalletContractState<'a>(pub &'a ExistingContract);

impl<'a> TokenWalletContractState<'a> {
    pub fn get_code_hash(&self) -> Result<ton_types::UInt256> {
        match &self.0.account.storage.state {
            ton_block::AccountState::AccountActive { state_init, .. } => {
                let code = state_init
                    .code
                    .as_ref()
                    .ok_or(TokenWalletError::WalletNotDeployed)?;
                Ok(code.repr_hash())
            }
            _ => Err(TokenWalletError::WalletNotDeployed.into()),
        }
    }

    pub fn get_balance(&self, clock: &dyn Clock, version: TokenWalletVersion) -> Result<BigUint> {
        let mut function = FunctionBuilder::new("balance")
            .default_headers()
            .output("value0", ton_abi::ParamType::Uint(128));

        let inputs = adjust_responsible(&mut function, version);

        let tokens = self.0.run_local(clock, &function.build(), &inputs)?;
        let data: TonTokenWalletBalance = tokens.unpack()?;

        Ok(data.balance)
    }

    pub fn get_details(
        &self,
        clock: &dyn Clock,
        version: TokenWalletVersion,
    ) -> Result<TokenWalletDetails> {
        let details_abi = TupleBuilder::new()
            .item("root_address", ton_abi::ParamType::Address)
            .item("wallet_public_key", ton_abi::ParamType::Uint(256))
            .item("owner_address", ton_abi::ParamType::Address)
            .item("balance", ton_abi::ParamType::Uint(128))
            .item("receive_callback", ton_abi::ParamType::Address)
            .item("bounced_callback", ton_abi::ParamType::Address)
            .item("allow_non_notifiable", ton_abi::ParamType::Bool);

        let mut function = FunctionBuilder::new("getDetails")
            .default_headers()
            .output("value0", details_abi.build());

        let inputs = adjust_responsible(&mut function, version);
        let outputs = self.0.run_local(clock, &function.build(), &inputs)?;

        let details = unpack_token_wallet_details(version, outputs)?;

        Ok(details)
    }

    pub fn get_version(&self, clock: &dyn Clock) -> Result<TokenWalletVersion> {
        // check Tip3v3+ version via direct call
        match get_version_direct(clock, self.0) {
            Ok(GotVersion::Known(version)) => return Ok(version),
            Ok(GotVersion::Unknown) => return Err(TokenWalletError::UnknownVersion.into()),
            _ => {} // fallback to Tip3v1 or Tip3v2
        };

        Err(TokenWalletError::UnknownVersion.into())
    }
}

fn unpack_token_wallet_details(
    _version: TokenWalletVersion,
    tokens: Vec<ton_abi::Token>,
) -> UnpackerResult<TokenWalletDetails> {
    let data: TonTokenWalletDetails = tokens.unpack_first()?;
    Ok(TokenWalletDetails {
        root_address: data.root_address,
        owner_address: data.owner_address,
        wallet_public_key: data.wallet_public_key,
        balance: data.balance,
    })
}

fn adjust_responsible(
    function: &mut FunctionBuilder,
    _version: TokenWalletVersion,
) -> Vec<ton_abi::Token> {
    function.make_responsible();
    vec![answer_id()]
}

fn get_version_direct(clock: &dyn Clock, contract: &ExistingContract) -> Result<GotVersion> {
    let function = FunctionBuilder::new_responsible("getVersion")
        .default_headers()
        .output("value0", ton_abi::ParamType::Uint(32))
        .build();

    let version: u32 = contract
        .run_local(clock, &function, &[answer_id()])?
        .unpack_first()?;

    Ok(version
        .try_into()
        .map(GotVersion::Known)
        .unwrap_or(GotVersion::Unknown))
}

enum GotVersion {
    Known(TokenWalletVersion),
    Unknown,
}

trait ExistingContractExt {
    fn run_local(
        &self,
        clock: &dyn Clock,
        function: &ton_abi::Function,
        input: &[ton_abi::Token],
    ) -> Result<Vec<ton_abi::Token>>;
}

impl ExistingContractExt for ExistingContract {
    fn run_local(
        &self,
        clock: &dyn Clock,
        function: &ton_abi::Function,
        input: &[ton_abi::Token],
    ) -> Result<Vec<ton_abi::Token>> {
        let ExecutionOutput {
            tokens,
            result_code,
        } = function.run_local(clock, self.account.clone(), input)?;
        tokens.ok_or_else(|| TokenWalletError::NonZeroResultCode(result_code).into())
    }
}

#[derive(thiserror::Error, Debug)]
enum TokenWalletError {
    #[error("Unknown version")]
    UnknownVersion,
    #[error("Invalid root token contract")]
    InvalidRootTokenContract,
    #[error("Invalid swap back destination")]
    InvalidSwapBackDestination,
    #[error("Non-zero execution result code: {}", .0)]
    NonZeroResultCode(i32),
    #[error("Wallet not deployed")]
    WalletNotDeployed,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use ton_block::Deserializable;

    use nekoton_abi::LastTransactionId;

    use super::*;

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
            TokenWalletVersion::OldTip3v4 => ROOT_TOKEN_STATE_TIP3_V4,
        };
        prepare_contract(data)
    }

    const ROOT_TOKEN_STATE_TIP3_V4: &str = "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";

    fn token_wallet_contract(version: TokenWalletVersion) -> ExistingContract {
        let data = match version {
            TokenWalletVersion::OldTip3v4 => TOKEN_WALLET_STATE_TIP3_V4,
        };
        prepare_contract(data)
    }

    const TOKEN_WALLET_STATE_TIP3_V4: &str = "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";

    #[test]
    fn get_token_wallet_balance() {
        let versions = [TokenWalletVersion::OldTip3v4];

        for &version in &versions {
            let contract = token_wallet_contract(version);
            let state = TokenWalletContractState(&contract);

            let parsed_version = state.get_version(&SimpleClock).unwrap();
            assert_eq!(parsed_version, version);

            state.get_details(&SimpleClock, parsed_version).unwrap();
            state.get_balance(&SimpleClock, version).unwrap();
        }
    }

    #[test]
    fn compute_token_wallet_address() {
        let owner_address = "0:a921453472366b7feeec15323a96b5dcf17197c88dc0d4578dfa52900b8a33cb";

        // pairs of token version and token wallet address
        let versions = [(
            TokenWalletVersion::OldTip3v4,
            "0:e4eb5f354e5f0335f38a73b6dc9808c67d611a717b5ed184d6210fb3e73067ee",
        )];

        // guess details from state for each version
        for &(version, token_wallet) in &versions {
            let contract = root_token_contract(version);
            let state = RootTokenContractState(&contract);

            let details = state.guess_details(&SimpleClock).unwrap();
            assert_eq!(details.version, version);

            let address = state
                .get_wallet_address(
                    &SimpleClock,
                    details.version,
                    &convert_address(owner_address),
                    None,
                )
                .unwrap();

            assert_eq!(address, convert_address(token_wallet));
        }
    }

    #[test]
    fn get_root_contract_details() {
        let root_state = r#"{"account":"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","timings":{"genLt":"16518174000001","genUtime":1626774889},"lastTransactionId":{"isExact":true,"lt":"16515724000001","hash":"2629f4c24ab0bfd30c13d71256ba1c878f526aeb3050ed134c54a1d5231828e1"}}"#;
        let root_state: ExistingContract = serde_json::from_str(root_state).unwrap();
        let root_state = RootTokenContractState(&root_state);
        let details = root_state.guess_details(&SimpleClock).unwrap();
        assert_eq!(
            details.total_supply,
            BigUint::from_str("6428633292").unwrap()
        );
        assert_eq!(details.decimals, 8);
        assert_eq!(details.version, TokenWalletVersion::OldTip3v4);
        assert_eq!(details.symbol, "WBTC");
    }

    #[test]
    fn get_strange_root_contract_details() {
        let root_state = r#"{"account":"te6ccgECpgEALrQAAnKAHh5eeOtBZE9N4jZNP+Kf124tRZChZNcAVHqtbpKGWoYGmYCwsgYPfoTgAAB4cmmGFjKAl0UXiSZgAQTzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwe+zxf4AAAAAAAAAAAAONfmkrtgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBfUVECAhD0pCCK7VP0oANhAgEgBwQBAv8FAv5/jQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE+Gkh2zzTAAGOHYECANcYIPkBAdMAAZTT/wMBkwL4QuIg+GX5EPKoldMAAfJ64tM/AY4d+EMhuSCfMCD4I4ED6KiCCBt3QKC53pMg+GPg8jTYMNMfAfgjvPK5EQYCFtMfAds8+EdujoDeCggDbt9wItDTA/pAMPhpqTgA+ER/b3GCCJiWgG9ybW9zcG90+GSOgOAhxwDcIdMfId0B2zz4R26OgN5ICggBBlvbPAkCDvhBbuMA2zxQSQRYIIIQDC/yDbuOgOAgghApxIl+u46A4CCCEEvxYOK7joDgIIIQebJe4buOgOA8KBQLBFAgghBotV8/uuMCIIIQce7odbrjAiCCEHVszfe64wIgghB5sl7huuMCEA8ODALqMPhBbuMA0x/4RFhvdfhk0fhEcG9ycG9xgEBvdPhk+Er4TPhN+E74UPhR+FJvByHA/45CI9DTAfpAMDHIz4cgzoBgz0DPgc+DyM+T5sl7hiJvJ1UGJ88WJs8L/yXPFiTPC3/IJM8WI88WIs8KAGxyzc3JcPsAUA0Bvo5W+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPg8j4RG8VzwsfIm8nVQYnzxYmzwv/Jc8WJM8Lf8gkzxYjzxYizwoAbHLNzcn4RG8U+wDiMOMAf/hnSQPiMPhBbuMA0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZPhN+kJvE9cL/8MAjoCS+ADibfhv+E36Qm8T1wv/jhX4ScjPhYjOgG3PQM+Bz4HJgQCA+wDe2zx/+GdQRUkCsDD4QW7jAPpBldTR0PpA39cMAJXU0dDSAN/R+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8uBk+AAh+HAg+HJb2zx/+GdQSQLiMPhBbuMA+Ebyc3H4ZtH4TPhCuiCOFDD4TfpCbxPXC//AACCVMPhMwADf3vLgZPgAf/hy+E36Qm8T1wv/ji34TcjPhYjOjQPInEAAAAAAAAAAAAAAAAABzxbPgc+Bz5EhTuze+ErPFslx+wDe2zx/+GcRSQGS7UTQINdJwgGOPNP/0z/TANX6QPpA+HH4cPht+kDU0//Tf/QEASBuldDTf28C3/hv1woA+HL4bvhs+Gv4an/4Yfhm+GP4Yo6A4hIB/vQFcSGAQPQOjiSNCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATf+GpyIYBA9A+SyMnf+GtzIYBA9A6T1wv/kXDi+Gx0IYBA9A6OJI0IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABN/4bXD4bm0TAM74b40IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPhwjQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE+HFw+HJwAYBA9A7yvdcL//hicPhjcPhmf/hhA0AgghA/ENGru46A4CCCEElpWH+7joDgIIIQS/Fg4rrjAiAZFQL+MPhBbuMA+kGV1NHQ+kDf1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/XDACV1NHQ0gDf1NH4TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y4GQkwgDy4GQk+E678uBlJfpCbxPXC//DAFAWAjLy4G8l+CjHBbPy4G/4TfpCbxPXC//DAI6AGBcB5I5o+CdvECS88uBuI4IK+vCAvPLgbvgAJPhOAaG1f/huIyZ/yM+FgMoAc89AzgH6AoBpz0DPgc+DyM+QY0hcCibPC3/4TM8L//hNzxYk+kJvE9cL/8MAkSSS+CjizxYjzwoAIs8Uzclx+wDiXwbbPH/4Z0kB7oIK+vCA+CdvENs8obV/tgn4J28QIYIK+vCAoLV/vPLgbiBy+wIl+E4BobV/+G4mf8jPhYDKAHPPQM6Abc9Az4HPg8jPkGNIXAonzwt/+EzPC//4Tc8WJfpCbxPXC//DAJElkvhN4s8WJM8KACPPFM3JgQCB+wAwmwIoIIIQP1Z5UbrjAiCCEElpWH+64wIcGgKQMPhBbuMA0x/4RFhvdfhk0fhEcG9ycG9xgEBvdPhk+E4hwP+OIyPQ0wH6QDAxyM+HIM6AYM9Az4HPgc+TJaVh/iHPC3/JcPsAUBsBgI43+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPgfhEbxXPCx8hzwt/yfhEbxT7AOIw4wB/+GdJBPww+EFu4wD6QZXU0dD6QN/XDX+V1NHQ03/f+kGV1NHQ+kDf1wwAldTR0NIA39TR+E9us/Lga/hJ+E8gbvJ/bxHHBfLgbCP4TyBu8n9vELvy4G0j+E678uBlI8IA8uBkJPgoxwWz8uBv+E36Qm8T1wv/wwCOgI6A4iP4TgGhtX9QHx4dAbT4bvhPIG7yf28QJKG1f/hPIG7yf28RbwL4byR/yM+FgMoAc89AzoBtz0DPgc+DyM+QY0hcCiXPC3/4TM8L//hNzxYkzxYjzwoAIs8UzcmBAIH7AF8F2zx/+GdJAi7bPIIK+vCAvPLgbvgnbxDbPKG1f3L7ApubAnKCCvrwgPgnbxDbPKG1f7YJ+CdvECGCCvrwgKC1f7zy4G4gcvsCggr68ID4J28Q2zyhtX+2CXL7AjCbmwIoIIIQLalNL7rjAiCCED8Q0au64wInIQL+MPhBbuMA1w3/ldTR0NP/3/pBldTR0PpA39cNf5XU0dDTf9/XDX+V1NHQ03/f1w1/ldTR0NN/3/pBldTR0PpA39cMAJXU0dDSAN/U0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZCXCAFAiAvzy4GQl+E678uBlJvpCbxPXC//AACCUMCfAAN/y4G/4TfpCbxPXC//DAI6AjiD4J28QJSWgtX+88uBuI4IK+vCAvPLgbif4TL3y4GT4AOJtKMjL/3BYgED0Q/hKcViAQPQW+EtyWIBA9BcoyMv/c1iAQPRDJ3RYgED0Fsj0AMkmIwH8+EvIz4SA9AD0AM+ByY0IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCbCAI43ISD5APgo+kJvEsjPhkDKB8v/ydAoIcjPhYjOAfoCgGnPQM+Dz4MizxTPgc+RotV8/slx+wAxMZ0h+QDIz4oAQMv/ydAx4vhNJAG4+kJvE9cL/8MAjlEn+E4BobV/+G4gf8jPhYDKAHPPQM6Abc9Az4HPg8jPkGNIXAopzwt/+EzPC//4Tc8WJvpCbxPXC//DAJEmkvhN4s8WJc8KACTPFM3JgQCB+wAlAbyOUyf4TgGhtX/4biUhf8jPhYDKAHPPQM4B+gKAac9Az4HPg8jPkGNIXAopzwt/+EzPC//4Tc8WJvpCbxPXC//DAJEmkvgo4s8WJc8KACTPFM3JcfsA4ltfCNs8f/hnSQFmggr68ID4J28Q2zyhtX+2CfgnbxAhggr68ICgtX8noLV/vPLgbif4TccFs/LgbyBy+wIwmwHoMNMf+ERYb3X4ZNF0IcD/jiMj0NMB+kAwMcjPhyDOgGDPQM+Bz4HPkralNL4hzwsfyXD7AI43+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPgfhEbxXPCx8hzwsfyfhEbxT7AOIw4wB/+GdJA0AgghAQR8kEu46A4CCCEBjSFwK7joDgIIIQKcSJfrrjAjQsKQL+MPhBbuMA+kGV1NHQ+kDf+kGV1NHQ+kDf1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/XDACV1NHQ0gDf1NH4TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y4GQl+kJvE9cL/8MA8uBvJFAqAvbCAPLgZCYmxwWz8uBv+E36Qm8T1wv/wwCOgI5X+CdvECS88uBuI4IK+vCAcqi1f7zy4G74ACMnyM+FiM4B+gKAac9Az4HPg8jPkP1Z5UYnzxYmzwt/JPpCbxPXC//DAJEkkvgo4s8WI88KACLPFM3JcfsA4l8H2zx/+GcrSQHMggr68ID4J28Q2zyhtX+2CfgnbxAhggr68IByqLV/oLV/vPLgbiBy+wInyM+FiM6Abc9Az4HPg8jPkP1Z5UYozxYnzwt/JfpCbxPXC//DAJElkvhN4s8WJM8KACPPFM3JgQCB+wAwmwIoIIIQGG1zvLrjAiCCEBjSFwK64wIyLQL+MPhBbuMA1w1/ldTR0NN/39cN/5XU0dDT/9/6QZXU0dD6QN/6QZXU0dD6QN/XDACV1NHQ0gDf1NEh+FKxIJww+FD6Qm8T1wv/wADf8uBwJCRtIsjL/3BYgED0Q/hKcViAQPQW+EtyWIBA9BciyMv/c1iAQPRDIXRYgED0Fsj0AFAuA77J+EvIz4SA9AD0AM+BySD5AMjPigBAy//J0DFsIfhJIccF8uBnJPhNxwWzIJUwJfhMvd/y4G/4TfpCbxPXC//DAI6AjoDiJvhOAaC1f/huIiCcMPhQ+kJvE9cL/8MA3jEwLwHIjkP4UMjPhYjOgG3PQM+Bz4PIz5FlBH7m+CjPFvhKzxYozwt/J88L/8gnzxb4Sc8WJs8WyPhOzwt/Jc8Uzc3NyYEAgPsAjhQjyM+FiM6Abc9Az4HPgcmBAID7AOIwXwbbPH/4Z0kBGPgnbxDbPKG1f3L7ApsBPIIK+vCA+CdvENs8obV/tgn4J28QIbzy4G4gcvsCMJsCrDD4QW7jANMf+ERYb3X4ZNH4RHBvcnBvcYBAb3T4ZPhPbrOW+E8gbvJ/jidwjQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEbwLiIcD/UDMB7o4sI9DTAfpAMDHIz4cgzoBgz0DPgc+Bz5Jhtc7yIW8iWCLPC38hzxZsIclw+wCOQPhEIG8TIW8S+ElVAm8RyHLPQMoAc89AzgH6AvQAgGjPQM+Bz4H4RG8VzwsfIW8iWCLPC38hzxZsIcn4RG8U+wDiMOMAf/hnSQIoIIIQDwJYqrrjAiCCEBBHyQS64wI6NQP2MPhBbuMA1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/6QZXU0dD6QN/U0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZCTCAPLgZCT4Trvy4GX4TfpCbxPXC//DACCOgN4gUDk2AmCOHTD4TfpCbxPXC//AACCeMCP4J28QuyCUMCPCAN7e3/LgbvhN+kJvE9cL/8MAjoA4NwHCjlf4ACT4TgGhtX/4biP4Sn/Iz4WAygBzz0DOAfoCgGnPQM+Bz4PIz5C4oiKqJs8Lf/hMzwv/+E3PFiT6Qm8T1wv/wwCRJJL4KOLPFsgkzxYjzxTNzclw+wDiXwXbPH/4Z0kBzIIK+vCA+CdvENs8obV/tgly+wIk+E4BobV/+G74Sn/Iz4WAygBzz0DOgG3PQM+Bz4PIz5C4oiKqJs8Lf/hMzwv/+E3PFiT6Qm8T1wv/wwCRJJL4TeLPFsgkzxYjzxTNzcmBAID7AJsBCjDbPMIAmwMuMPhBbuMA+kGV1NHQ+kDf0ds82zx/+GdQO0kAvPhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZPhOwADy4GT4ACDIz4UIzo0DyA+gAAAAAAAAAAAAAAAAAc8Wz4HPgcmBAKD7ADADPiCCCyHRc7uOgOAgghALP89Xu46A4CCCEAwv8g264wJCPz0D/jD4QW7jANcNf5XU0dDTf9/6QZXU0dD6QN/6QZXU0dD6QN/U0fhK+EnHBfLgZiPCAPLgZCP4Trvy4GX4J28Q2zyhtX9y+wIj+E4BobV/+G74Sn/Iz4WAygBzz0DOgG3PQM+Bz4PIz5C4oiKqJc8Lf/hMzwv/+E3PFiTPFsgkzxZQmz4BJCPPFM3NyYEAgPsAXwTbPH/4Z0kCKCCCEAXFAA+64wIgghALP89XuuMCQUACVjD4QW7jANcNf5XU0dDTf9/R+Er4SccF8uBm+AAg+E4BoLV/+G4w2zx/+GdQSQKWMPhBbuMA+kGV1NHQ+kDf0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZPgAIPhxMNs8f/hnUEkCJCCCCXwzWbrjAiCCCyHRc7rjAkZDA/Aw+EFu4wD6QZXU0dD6QN/XDX+V1NHQ03/f1w1/ldTR0NN/39H4TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y4GQhwAAgljD4T26zs9/y4Gr4TfpCbxPXC//DAI6AkvgA4vhPbrNQRUQBiI4S+E8gbvJ/bxAiupYgI28C+G/eliAjbwL4b+L4TfpCbxPXC/+OFfhJyM+FiM6Abc9Az4HPgcmBAID7AN5fA9s8f/hnSQEmggr68ID4J28Q2zyhtX+2CXL7ApsC/jD4QW7jANMf+ERYb3X4ZNH4RHBvcnBvcYBAb3T4ZPhLIcD/jiIj0NMB+kAwMcjPhyDOgGDPQM+Bz4HPkgXwzWYhzxTJcPsAjjb4RCBvEyFvEvhJVQJvEchyz0DKAHPPQM4B+gL0AIBoz0DPgc+B+ERvFc8LHyHPFMn4RG8U+wBQRwEO4jDjAH/4Z0kEQCHWHzH4QW7jAPgAINMfMiCCEBjSFwK6joCOgOIwMNs8UExKSQCs+ELIy//4Q88LP/hGzwsAyPhN+FD4UV4gzs7O+Er4S/hM+E74T/hSXmDPEc7My//LfwEgbrOOFcgBbyLIIs8LfyHPFmwhzxcBz4PPEZMwz4HiygDJ7VQBFiCCEC4oiKq6joDeSwEwIdN/M/hOAaC1f/hu+E36Qm8T1wv/joDeTgI8IdN/MyD4TgGgtX/4bvhR+kJvE9cL/8MAjoCOgOIwT00BGPhN+kJvE9cL/46A3k4BUIIK+vCA+CdvENs8obV/tgly+wL4TcjPhYjOgG3PQM+Bz4HJgQCA+wCbAYD4J28Q2zyhtX9y+wL4UcjPhYjOgG3PQM+Bz4PIz5DqFdlC+CjPFvhKzxYizwt/yPhJzxb4Ts8Lf83NyYEAgPsAmwB+7UTQ0//TP9MA1fpA+kD4cfhw+G36QNTT/9N/9AQBIG6V0NN/bwLf+G/XCgD4cvhu+Gz4a/hqf/hh+Gb4Y/hiAf6qTG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4gTWF1cmlzIGV0IGR1aSBlZ2V0IG5pYmggdGVtcHVzIHB1bHZpbmFyLiBRdWlzcXVlIHVsbGFtY29ycGVyLCBkb2xvciBzUgH+ZWQgdm9sdXRwYXQgdm9sdXRwYXQsIGV4IG1hdXJpcyBwb3N1ZXJlIGV4LCBldSB1bHRyaWNpZXMgZGlhbSBuZXF1ZSBtb2xlc3RpZSBtaS4gTWFlY2VuYXMgYSBibGFuZGl0IG1hc3NhLiBGdXNjZSBhdCB2ZWxpdCB0b3J0b1MB/nIuIExvcmVtIGlwc3VtIGRvbG9yIHNpdCBhbWV0LCBjb25zZWN0ZXR1ciBhZGlwaXNjaW5nIGVsaXQuIEFlbmVhbiBzY2VsZXJpc3F1ZSBkaWN0dW0gcmlzdXMgcXVpcyBoZW5kcmVyaXQuIER1aXMgaW50ZXJkdW0gZWxlaWZUAf5lbmQgZW5pbS4gRnVzY2UgdmVsIGZlbGlzIGNvbW1vZG8sIGZlcm1lbnR1bSB2ZWxpdCBzdXNjaXBpdCwgaW1wZXJkaWV0IGxlby4gTWFlY2VuYXMgdml0YWUgcHVydXMgdml0YWUgbWV0dXMgbWFsZXN1YWRhIGZldWdpYXQuVQH+IFZlc3RpYnVsdW0gYW50ZSBpcHN1bSBwcmltaXMgaW4gZmF1Y2lidXMgb3JjaSBsdWN0dXMgZXQgdWx0cmljZXMgcG9zdWVyZSBjdWJpbGlhIGN1cmFlOyBWZXN0aWJ1bHVtIHNlZCBkaWFtIHZpdGFlIGxhY3VzIG1vbGVzdFYB/mllIHZhcml1cyBldSBhdCBlcmF0LiBOdWxsYSBsdWN0dXMgcGVsbGVudGVzcXVlIG5pYmggdmVsIHNvZGFsZXMuIFZlc3RpYnVsdW0gYW50ZSBvcmNpLCBwbGFjZXJhdCBhYyBydXRydW0gZWdldCwgYmliZW5kdW0gaW4gYW5XAf50ZS4gTWF1cmlzIG1hdHRpcyBtYXNzYSBldCB0b3J0b3IgbW9sbGlzIGZpbmlidXMuqlBoYXNlbGx1cyBiaWJlbmR1bSBsaWd1bGEgdG9ydG9yLCBpZCB2ZWhpY3VsYSBhcmN1IGNvbnNlcXVhdCBlbGVtZW50dW0uIEFsaXF1WAH+YW0gdnVscHV0YXRlIGhlbmRyZXJpdCBhcmN1IGlkIGZldWdpYXQuIEV0aWFtIGNvbW1vZG8gbG9ib3J0aXMgZWdlc3Rhcy4gSW4gYSBudWxsYSB0ZW1wb3IsIGZyaW5naWxsYSBkdWkgZXUsIGxvYm9ydGlzIHVybmEuIE1hZVkB/mNlbmFzIG9ybmFyZSwgbWkgYWMgdml2ZXJyYSBhdWN0b3IsIGV4IHNlbSBzb2RhbGVzIG9yY2ksIHF1aXMgcnV0cnVtIG1pIHZlbGl0IGEgbmliaC4gRHVpcyBpYWN1bGlzLCBzZW0gZ3JhdmlkYSBpbXBlcmRpZXQgY29uZGlaAf5tZW50dW0sIGlwc3VtIGRpYW0gdWxsYW1jb3JwZXIgZHVpLCBhdCBlbGVtZW50dW0gc2VtIHB1cnVzIHNlZCBhcmN1LiBEb25lYyB2ZWwgb3JuYXJlIG1hZ25hLiBDdXJhYml0dXIgY29uc2VjdGV0dXIgbmVjIG1hZ25hIGF0WwH+IHVsdHJpY2VzLiBJbnRlZ2VyIG5lYyBmaW5pYnVzIHRlbGx1cy4gSW50ZWdlciB2aXRhZSBtYXR0aXMgZHVpLCB2aXRhZSB0cmlzdGlxdWUgbWkuIFNlZCBuaWJoIG9yY2ksIGVsZW1lbnR1bSBub24gbmlzaSBhYywgZmFjaVwB/mxpc2lzIHBvc3VlcmUgbG9yZW0uIFV0IHNhcGllbiBmZWxpcywgdWxsYW1jb3JwZXIgaWQgbGFjdXMgZXQsIGF1Y3RvciBkaWduaXNzaW0gZGlhbS4gVml2YW11cyBuZWMgdXJuYSBuZXF1ZS4gTnVuYyBtYXVyaXMgb3JjaSxdAf4gZGljdHVtIG5vbiB1cm5hIHZlbCwgdmFyaXVzIHRpbmNpZHVudCBtaS4gU3VzcGVuZGlzc2UgdWx0cmljaWVzIG51bGxhIG1pLCBpZCBzZW1wZXIgbWFzc2Egc2FnaXR0aXMgdXQuIFNlZCBmYWNpbGlzaXMgdGVsbHVzIHV0XgA2IG1ldHVzIGZlcm1lbnR1bSBpbnRlcmR1bS4gAGOAE1v3A5m4uXTpo3Ifu8Brbi0ngv0nlmNbRglcPELhQ3NAAAAAAAAAAAAAAAAO5rKAEAIQ9KQgiu1T9KBjYQEK9KQg9KFiAAACASBnZAEC/2UC/n+NCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAT4aSHbPNMAAY4dgQIA1xgg+QEB0wABlNP/AwGTAvhC4iD4ZfkQ8qiV0wAB8nri0z8Bjh34QyG5IJ8wIPgjgQPoqIIIG3dAoLnekyD4Y+DyNNgw0x8B+CO88rmeZgIW0x8B2zz4R26OgN5qaANu33Ai0NMD+kAw+GmpOAD4RH9vcYIImJaAb3Jtb3Nwb3T4ZI6A4CHHANwh0x8h3QHbPPhHbo6A3qNqaAEGW9s8aQIO+EFu4wDbPKWkBFggghAVAFsHu46A4CCCEDMfUaS7joDgIIIQcj3EzruOgOAgghB/96R8u46A4JKEcGsDPCCCEHJuk3+64wIgghB5hbP0uuMCIIIQf/ekfLrjAm9ubALcMPhBbuMA0x/4RFhvdfhk0fhEcG9ycG9xgEBvdPhk+Ev4TPhN+FD4UfhPbwYhwP+OPSPQ0wH6QDAxyM+HIM6AYM9Az4HPg8jPk//ekfIibyZVBSbPFCXPFCTPCwcjzwv/Is8WIc8Lf2xhzclw+wClbQG0jlH4RCBvEyFvEvhJVQJvEchyz0DKAHPPQM4B+gL0AIBoz0DPgc+DyPhEbxXPCx8ibyZVBSbPFCXPFCTPCwcjzwv/Is8WIc8Lf2xhzcn4RG8U+wDiMOMAf/hnpAFmMNHbPCDA/44l+EvIi9wAAAAAAAAAAAAAAAAgzxbPgc+Bz5PmFs/SIc8UyXD7AN4wf/hnpQFoMNHbPCDA/44m+FLIi9wAAAAAAAAAAAAAAAAgzxbPgc+Bz5PJuk3+Ic8Lf8lw+wDeMH/4Z6UDQiCCEEWzvf27joDgIIIQVbOp+7uOgOAgghByPcTOu46A4IB6cQIoIIIQZiEcb7rjAiCCEHI9xM664wJ0cgL8MPhBbuMA1w1/ldTR0NN/3/pBldTR0PpA39H4UfpCbxPXC//DACCXMPhR+EnHBd4gjhQw+FDDACCcMPhQ+EUgbpIwcN663t/y4GT4ACDIz4WIzo0EDmJaAAAAAAAAAAAAAAAAAAHPFs+Bz4HPkCz/PV4izwt/yXD7ACH4TwGgpXMBFLV/+G9b2zx/+GekAuIw+EFu4wDXDX+V1NHQ03/f1w1/ldTR0NN/39cN/5XU0dDT/9/6QZXU0dD6QN/6QZXU0dD6QN/RjQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE+FH6Qm8T1wv/wwAglzD4UfhJxwXeIKV1AvyOFDD4UMMAIJww+FD4RSBukjBw3rre3/LgZCVwvvLgZCL6Qm8T1wv/wwAglDAjwADeII4SMCL6Qm8T1wv/wAAglDAjwwDe3/LgZ/hR+kJvE9cL/8AAkvgAjoDibSTIy/9wWIBA9EP4KHFYgED0FvhOcliAQPQXJMjL/3NYgEB5dgH09EMjdFiAQPQWyPQAyfhOyM+EgPQA9ADPgcmNCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQmwgCONyEg+QD4KPpCbxLIz4ZAygfL/8nQKCHIz4WIzgH6AoBpz0DPg8+DIs8Uz4HPkaLVfP7JcfsAMTF3AZydIfkAyM+KAEDL/8nQMeIgyM+FiM6NBA5iWgAAAAAAAAAAAAAAAAABzxbPgc+Bz5As/z1eKM8Lf8lw+wAn+E8BoLV/+G/4UfpCbxPXC/94AeCOOCP6Qm8T1wv/wwCOFCPIz4WIzoBtz0DPgc+ByYEAgPsAjhX4ScjPhYjOgG3PQM+Bz4HJgQCA+wDi3iBsE1lbbFEhwP+OIiPQ0wH6QDAxyM+HIM6AYM9Az4HPgc+TmIRxviHPFslw+wDeMNs8f/hnpAEg+FL4J28Q2zyhtX+2CXL7ApsCKCCCEFQrFnK64wIgghBVs6n7uuMCfXsD/jD4QW7jANcN/5XU0dDT/9/6QZXU0dD6QN/6QZXU0dD6QN/R+CdvENs8obV/cvsCIiJtIsjL/3BYgED0Q/gocViAQPQW+E5yWIBA9BciyMv/c1iAQPRDIXRYgED0Fsj0AMn4TsjPhID0APQAz4HJIPkAyM+KAEDL/8nQMWwhIcilm3wBWM+FiM6Abc9Az4HPg8jPkEXN5XIizxYlzwv/JM8WzcmBAID7ADBfA9s8f/hnpAP+MPhBbuMA1w1/ldTR0NN/39cN/5XU0dDT/9/6QZXU0dD6QN/6QZXU0dD6QN/RIfpCbxPXC//DACCUMCLAAN4gjhIwIfpCbxPXC//AACCUMCLDAN7f8uBn+CdvENs8obV/cvsCbSPIy/9wWIBA9EP4KHFYgED0FvhOcliAQPQXI6WbfgHeyMv/c1iAQPRDInRYgED0Fsj0AMn4TsjPhID0APQAz4HJIPkAyM+KAEDL/8nQJSHIz4WIzgH6AoBpz0DPg8+DIs8Uz4HPkaLVfP7JcfsAMSH6Qm8T1wv/wwCOFCHIz4WIzoBtz0DPgc+ByYEAgPsAfwGUjhX4ScjPhYjOgG3PQM+Bz4HJgQCA+wDiIDFsQSHA/44iI9DTAfpAMDHIz4cgzoBgz0DPgc+Bz5NQrFnKIc8WyXD7AN4w2zx/+GekAiggghA4KCYauuMCIIIQRbO9/brjAoKBAWYw0ds8IMD/jiX4TMiL3AAAAAAAAAAAAAAAACDPFs+Bz4HPkxbO9/YhzxTJcPsA3jB/+GelA/4w+EFu4wDXDf+V1NHQ0//f+kGV1NHQ+kDf0fhR+kJvE9cL/8MAIJcw+FH4SccF3iCOFDD4UMMAIJww+FD4RSBukjBw3rre3/LgZCHDACCbMCD6Qm8T1wv/wADeII4SMCHAACCbMCD6Qm8T1wv/wwDe3/LgZ/gAIfhwIPhxW9s8paSDAAZ/+GcDQiCCECDrx227joDgIIIQLiiIqruOgOAgghAzH1Gku46A4I6JhQIoIIIQMI1m0brjAiCCEDMfUaS64wKIhgKQMPhBbuMA0x/4RFhvdfhk0fhEcG9ycG9xgEBvdPhk+E8hwP+OIyPQ0wH6QDAxyM+HIM6AYM9Az4HPgc+SzH1GkiHPC3/JcPsApYcBgI43+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPgfhEbxXPCx8hzwt/yfhEbxT7AOIw4wB/+GekAWgw0ds8IMD/jib4U8iL3AAAAAAAAAAAAAAAACDPFs+Bz4HPksI1m0YhzwoAyXD7AN4wf/hnpQIoIIIQLalNL7rjAiCCEC4oiKq64wKNigL+MPhBbuMA1w1/ldTR0NN/39cN/5XU0dDT/9/6QZXU0dD6QN/6QZXU0dD6QN/6QZXU0dD6QN/U0fhTs/LgaCQkbSLIy/9wWIBA9EP4KHFYgED0FvhOcliAQPQXIsjL/3NYgED0QyF0WIBA9BbI9ADJ+E7Iz4SA9AD0AM+BySD5AKWLAv7Iz4oAQMv/ydAxbCH4SSHHBfLgZvgnbxDbPKG1f3L7Aib4TwGhtX/4byL6Qm8T1wv/wACOFCPIz4WIzoBtz0DPgc+ByYEAgPsAjjIiyM+FiM6Abc9Az4HPg8jPkPMkQPoozwt/I88UJ88L/ybPFiLPFsgmzxbNzcmBAID7AOIwm4wBDl8G2zx/+GekAegw0x/4RFhvdfhk0XQhwP+OIyPQ0wH6QDAxyM+HIM6AYM9Az4HPgc+StqU0viHPCx/JcPsAjjf4RCBvEyFvEvhJVQJvEchyz0DKAHPPQM4B+gL0AIBoz0DPgc+B+ERvFc8LHyHPCx/J+ERvFPsA4jDjAH/4Z6QCKCCCEB34aKm64wIgghAg68dtuuMCkI8CmjD4QW7jAPpBldTR0PpA39H4UfpCbxPXC//DACCXMPhR+EnHBd7y4GT4UnL7AiDIz4WIzoBtz0DPgc+Bz5A7trPyyYEAgPsAMNs8f/hnpaQD/DD4QW7jANcNf5XU0dDTf9/6QZXU0dD6QN/6QZXU0dD6QN/6QZXU0dD6QN/U0fhR+kJvE9cL/8MAIJcw+FH4SccF3vLgZPgnbxDbPKG1f3L7AiJwJW0iyMv/cFiAQPRD+ChxWIBA9Bb4TnJYgED0FyLIy/9zWIBA9EMhdFiAQKWbkQG+9BbI9ADJ+E7Iz4SA9AD0AM+BySD5AMjPigBAy//J0DFsIST6Qm8T1wv/kiUy3yDIz4WIzoBtz0DPgc+DyM+QML/INijPC38jzxYlzxYkzxTNyYEAgPsAW18F2zx/+GekA0AgggnVPR27joDgIIIQBpoI+LuOgOAgghAVAFsHu46A4JyWkwIoIIIQDVr8crrjAiCCEBUAWwe64wKVlAFoMNHbPCDA/44m+E3Ii9wAAAAAAAAAAAAAAAAgzxbPgc+Bz5JUAWweIc8LB8lw+wDeMH/4Z6UCiDD4QW7jANIA0fhR+kJvE9cL/8MAIJcw+FH4SccF3iCOFDD4UMMAIJww+FD4RSBukjBw3rre3/LgZPgAIPhzMNs8f/hnpaQCJiCCCfUaZrrjAiCCEAaaCPi64wKalwL8MPhBbuMA0x/4RFhvdfhk1w3/ldTR0NP/3/pBldTR0PpA39Eg+kJvE9cL/8MAIJQwIcAA3iCOEjAg+kJvE9cL/8AAIJQwIcMA3t/y4Gf4RHBvcnBvcYBAb3T4ZCEhbSLIy/9wWIBA9EP4KHFYgED0FvhOcliAQPQXIsjL/3NYpZgBqIBA9EMhdFiAQPQWyPQAyfhOyM+EgPQA9ADPgckg+QDIz4oAQMv/ydAxbCFsISHA/44iI9DTAfpAMDHIz4cgzoBgz0DPgc+Bz5IaaCPiIc8WyXD7AJkBfo42+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPgfhEbxXPCx8hzxbJ+ERvFPsA4jDjAH/4Z6QDjjD4QW7jANM/+kGV1NHQ+kDf0fgnbxDbPKG1f3L7AiDIz4WIzoBtz0DPgc+Bz5HOG8OiIs8LP/hTzwoAyYEAgPsAW9s8f/hnpZukABhwaKb7YJVopv5gMd8CJCCCCXwzWbrjAiCCCdU9HbrjAqGdAsow+EFu4wD4RvJzcfhm1w3/ldTR0NP/3/pBldTR0PpA39EhwwAgmzAg+kJvE9cL/8AA3iCOEjAhwAAgmzAg+kJvE9cL/8MA3t/y4Gf4ACH4cCD4cXD4b3D4c/gnbxD4clvbPH/4Z56kAYjtRNAg10nCAY430//TP9MA1fpA1wt/+HL4cdP/1NTTB9TTf9P/1woA+HP4cPhv+G74bfhs+Gv4an/4Yfhm+GP4Yo6A4p8B/PQFcSGAQPQOk9cL/5Fw4vhqciGAQPQPksjJ3/hrcyGAQPQPksjJ3/hsdCGAQPQOk9cLB5Fw4vhtdSGAQPQPksjJ3/hucPhvcPhwjQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE+HFw+HJw+HNwAYBA9A7yvaAAHNcL//hicPhjcPhmf/hhAv4w+EFu4wDTH/hEWG91+GTR+ERwb3Jwb3GAQG90+GT4TiHA/44iI9DTAfpAMDHIz4cgzoBgz0DPgc+Bz5IF8M1mIc8UyXD7AI42+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPgfhEbxXPCx8hzxTJ+ERvFPsApaIBDuIw4wB/+GekAlYh1h8x+EFu4wD4ACDTHzIgghALP89Xup4h038zIPhPAaG1f/hvMN4wMNs8paQAePhCyMv/+EPPCz/4Rs8LAMj4UfhSAs7Lf/hK+Ev4TPhN+E74T/hQ+FNegM8Ry//MzMsHzMt/y//KAMntVAB07UTQ0//TP9MA1fpA1wt/+HL4cdP/1NTTB9TTf9P/1woA+HP4cPhv+G74bfhs+Gv4an/4Yfhm+GP4Yg==","timings":{"genLt":"16558098000001","genUtime":1626868952},"lastTransactionId":{"isExact":true,"lt":"16554099000005","hash":"a73789af4437ff5a58f33a5b29a347d01b6b99088009437b8e47d73751f51741"}}"#;
        let root_state: ExistingContract = serde_json::from_str(root_state).unwrap();
        let root_state = RootTokenContractState(&root_state);
        root_state.guess_details(&SimpleClock).unwrap();
    }

    #[test]
    fn get_token_wallet_address_pubkey() {
        let owner_address = MsgAddressInt::from_str(
            "0:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let pubkey =
            hex::decode("c1f6343e4fd59902c359ec39aa4544f3d8c82f27ffecd96728930ed7a42c25ca")
                .unwrap();
        let contract = r#"{"account":"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","timings":{"genLt":"0","genUtime":0},"lastTransactionId":{"isExact":false,"lt":"14207312000003"}}"#;
        let contract: ExistingContract = serde_json::from_str(contract).unwrap();
        let root = RootTokenContractState(&contract);
        root.get_wallet_address(
            &SimpleClock,
            TokenWalletVersion::OldTip3v4,
            &owner_address,
            Some(&pubkey),
        )
        .unwrap();
    }
}
