use std::convert::TryInto;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use num_bigint::BigUint;
use ton_block::MsgAddressInt;

use super::AccountSubscription;
use crate::core::models::{
    AccountState, GenTimings, LastTransactionId, PendingTransaction, PollingMethod, Symbol,
    TokenWalletDetails, TokenWalletState, TokenWalletVersion, Transaction, TransactionId,
    TransactionsBatchInfo,
};
use crate::helpers::abi;
use crate::helpers::abi::{FunctionArg, FunctionExt, IntoParser, TokenValueExt, TupleBuilder};
use crate::transport::models::ContractState;
use crate::transport::Transport;

pub struct TokenWallet {
    address: MsgAddressInt,
    symbol: Symbol,
    owner: MsgAddressInt,
}

impl TokenWallet {
    pub fn new(address: MsgAddressInt, symbol: Symbol, owner: MsgAddressInt) -> Self {
        Self {
            address,
            symbol,
            owner,
        }
    }

    pub fn address(&self) -> &MsgAddressInt {
        &self.address
    }

    pub fn symbol(&self) -> &Symbol {
        &self.symbol
    }

    pub fn owner(&self) -> &MsgAddressInt {
        &self.owner
    }
}

#[derive(Clone)]
pub struct TokenWalletSubscription {
    transport: Arc<dyn Transport>,
    handler: Arc<dyn TokenWalletSubscriptionHandler>,
    address: MsgAddressInt,
    account_state: TokenWalletState,
    latest_known_transaction: Option<TransactionId>,
    pending_transactions: Vec<PendingTransaction>,
}

impl TokenWalletSubscription {
    pub async fn refresh_account_state(&mut self) -> Result<bool> {
        let new_state = match self.transport.get_account_state(&self.address).await? {
            ContractState::NotExists => TokenWalletState {
                balance: Default::default(),
                proxy_address: Default::default(),
                account_state: AccountState {
                    balance: 0,
                    gen_timings: GenTimings::Unknown,
                    last_transaction_id: None,
                    is_deployed: false,
                },
            },
            ContractState::Exists {
                account,
                timings,
                last_transaction_id,
            } => {
                todo!()
            }
        };

        todo!()
    }
}

#[async_trait]
impl AccountSubscription for TokenWalletSubscription {
    async fn send(
        &mut self,
        message: &ton_block::Message,
        expire_at: u32,
    ) -> Result<PendingTransaction> {
        todo!()
    }

    async fn refresh(&mut self) -> Result<()> {
        todo!()
    }

    async fn handle_block(&mut self, block: &ton_block::Block) -> Result<()> {
        todo!()
    }

    fn polling_method(&self) -> PollingMethod {
        todo!()
    }
}

pub trait TokenWalletSubscriptionHandler: Send + Sync {
    /// Called every time a new state is detected
    fn on_state_changed(&self, new_state: TokenWalletState);

    /// Called every time new transactions are detected.
    /// - When new block found
    /// - When manually requesting the latest transactions (can be called several times)
    /// - When preloading transactions
    fn on_transactions_found(
        &self,
        transactions: Vec<Transaction>,
        batch_info: TransactionsBatchInfo,
    );
}

fn adjust_responsible(
    function: &mut abi::FunctionBuilder,
    version: TokenWalletVersion,
) -> Vec<ton_abi::Token> {
    let mut inputs = Vec::new();
    match version {
        TokenWalletVersion::Tip3v1 | TokenWalletVersion::Tip3v2 => {}
        _ => {
            function.make_responsible();
            inputs.push(abi::answer_id());
        }
    }
    inputs
}

fn get_token_wallet_balance(
    account_state: ton_block::AccountStuff,
    timings: GenTimings,
    last_transaction_id: &LastTransactionId,
    version: TokenWalletVersion,
) -> Result<BigUint> {
    let mut function = abi::FunctionBuilder::new("balance")
        .default_headers()
        .out_arg("value0", ton_abi::ParamType::Uint(128));

    let inputs = adjust_responsible(&mut function, version);

    let balance = function
        .build()
        .run_local(account_state, timings, last_transaction_id, &inputs)?
        .into_parser()
        .parse_next()?;

    Ok(balance)
}

fn get_token_wallet_details(
    account_state: ton_block::AccountStuff,
    timings: GenTimings,
    last_transaction_id: &LastTransactionId,
    version: TokenWalletVersion,
) -> Result<TokenWalletDetails> {
    let mut details_abi = TupleBuilder::new()
        .arg("root_address", ton_abi::ParamType::Address)
        .arg("code", ton_abi::ParamType::Cell)
        .arg("wallet_public_key", ton_abi::ParamType::Uint(256))
        .arg("owner_address", ton_abi::ParamType::Address)
        .arg("balance", ton_abi::ParamType::Uint(128));

    match version {
        TokenWalletVersion::Tip3v1 => {}
        _ => {
            details_abi = details_abi
                .arg("receive_callback", ton_abi::ParamType::Address)
                .arg("bounced_callback", ton_abi::ParamType::Address)
                .arg("allow_non_notifiable", ton_abi::ParamType::Bool);
        }
    }

    let mut function = abi::FunctionBuilder::new("getDetails")
        .default_headers()
        .out_arg("value0", details_abi.build());

    let inputs = adjust_responsible(&mut function, version);

    let details = function
        .build()
        .run_local(account_state, timings, last_transaction_id, &inputs)?
        .into_parser()
        .parse_next()?;

    Ok(details)
}

impl abi::ParseToken<TokenWalletDetails> for ton_abi::TokenValue {
    fn try_parse(self) -> abi::ContractResult<TokenWalletDetails> {
        let mut tuple = match self {
            ton_abi::TokenValue::Tuple(tokens) => tokens.into_parser(),
            _ => return Err(abi::ParserError::InvalidAbi),
        };

        let root_address = tuple.parse_next()?;
        let _code: ton_types::Cell = tuple.parse_next()?;
        let _wallet_public_key: ton_types::UInt256 = tuple.parse_next()?;
        let owner_address = tuple.parse_next()?;

        Ok(TokenWalletDetails {
            root_address,
            owner_address,
        })
    }
}

fn get_token_wallet_version(
    account_state: &ton_block::AccountStuff,
    gen_timings: GenTimings,
    last_transaction_id: &LastTransactionId,
) -> Result<TokenWalletVersion> {
    // check Tip3v3+ version via direct call
    match get_version_direct(account_state.clone(), gen_timings, last_transaction_id) {
        Ok(GotVersion::Known(version)) => return Ok(version),
        Ok(GotVersion::Unknown) => return Err(TokenWalletError::UnknownVersion.into()),
        _ => {} // fallback to Tip3v1 or Tip3v2
    };

    // check Tip3v2 version via getDetails
    let mut version = TokenWalletVersion::Tip3v2;
    if get_token_wallet_details(
        account_state.clone(),
        gen_timings,
        last_transaction_id,
        version,
    )
    .is_ok()
    {
        return Ok(version);
    }

    // check Tip3v3 version via getDetails
    version = TokenWalletVersion::Tip3v1;
    if get_token_wallet_details(
        account_state.clone(),
        gen_timings,
        last_transaction_id,
        version,
    )
    .is_ok()
    {
        return Ok(version);
    }

    Err(TokenWalletError::UnknownVersion.into())
}

fn get_version_direct(
    account_state: ton_block::AccountStuff,
    gen_timings: GenTimings,
    last_transaction_id: &LastTransactionId,
) -> Result<GotVersion> {
    let version: u32 = abi::FunctionBuilder::new("getVersion")
        .default_headers()
        .responsible()
        .out_arg("value0", ton_abi::ParamType::Uint(32))
        .build()
        .run_local(
            account_state,
            gen_timings,
            last_transaction_id,
            &[abi::answer_id()],
        )?
        .into_parser()
        .parse_next()?;

    Ok(version
        .try_into()
        .map(GotVersion::Known)
        .unwrap_or(GotVersion::Unknown))
}

enum GotVersion {
    Known(TokenWalletVersion),
    Unknown,
}

#[derive(thiserror::Error, Debug)]
enum TokenWalletError {
    #[error("Unknown version")]
    UnknownVersion,
}
