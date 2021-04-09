use std::convert::TryInto;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use futures::{Stream, StreamExt};
use num_bigint::BigUint;
use ton_block::{Deserializable, GetRepresentationHash, MsgAddressInt, Serializable};

use super::utils;
use crate::contracts;
use crate::core::models::{
    AccountState, GenTimings, LastTransactionId, PendingTransaction, PollingMethod,
    RootTokenContractDetails, Symbol, TokenWalletDetails, TokenWalletState, TokenWalletVersion,
    Transaction, TransactionId, TransactionsBatchInfo,
};
use crate::helpers::abi;
use crate::helpers::abi::{FunctionArg, FunctionExt, IntoParser, TokenValueExt, TupleBuilder};
use crate::transport::models::{ContractState, ExistingContract};
use crate::transport::Transport;
use crate::utils::{NoFailure, TrustMe};

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
    symbol: Symbol,
    version: TokenWalletVersion,
    root_meta_address: MsgAddressInt,
    wallet_state: TokenWalletState,
    latest_known_transaction: Option<TransactionId>,
    pending_transactions: Vec<PendingTransaction>,
}

impl TokenWalletSubscription {
    pub async fn refresh_account_state(&mut self) -> Result<bool> {
        let new_state = match self.transport.get_contract_state(&self.address).await? {
            ContractState::NotExists => TokenWalletState::default(),
            ContractState::Exists(state) => {
                let account_state = state.account_state();
                let balance = TokenWalletContractState(&state).get_balance(self.version)?;
                TokenWalletState {
                    balance,
                    account_state,
                }
            }
        };

        Ok(if new_state != self.wallet_state {
            self.wallet_state = new_state;
            self.handler.on_state_changed(self.wallet_state.clone());
            true
        } else {
            false
        })
    }

    pub async fn get_proxy_address(&mut self) -> Result<MsgAddressInt> {
        match self
            .transport
            .get_contract_state(&self.root_meta_address)
            .await?
        {
            ContractState::Exists(state) => {
                Ok(RootMetaContractState(&state).get_details()?.proxy_address)
            }
            _ => return Err(TokenWalletError::InvalidRootMetaContract.into()),
        }
    }

    pub async fn refresh_latest_transactions(
        &mut self,
        initial_count: u8,
        limit: Option<usize>,
    ) -> Result<()> {
        let from = match self.wallet_state.account_state.last_transaction_id {
            Some(id) => id.to_transaction_id(),
            None => return Ok(()),
        };

        let mut new_latest_known_transaction = None;

        // clone request context, because `&mut self` is needed later
        let transport = self.transport.clone();
        let address = self.address.clone();
        let latest_known_transaction = self.latest_known_transaction;

        let mut transactions = utils::request_transactions(
            transport.as_ref(),
            &address,
            from,
            latest_known_transaction.as_ref(),
            initial_count,
            limit,
        );

        while let Some((new_transactions, batch_info)) = transactions.next().await {
            let new_transactions =
                utils::convert_transactions(new_transactions).collect::<Vec<_>>();
            if new_transactions.is_empty() {
                continue;
            }

            if new_latest_known_transaction.is_none() {
                new_latest_known_transaction =
                    new_transactions.first().map(|transaction| transaction.id);
            }

            self.handler
                .on_transactions_found(new_transactions, batch_info);
        }

        std::mem::drop(transactions);

        if let Some(id) = new_latest_known_transaction {
            self.latest_known_transaction = Some(id);
        }

        Ok(())
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

struct RootTokenContractState<'a>(&'a ExistingContract);

impl<'a> RootTokenContractState<'a> {
    /// Calculates token wallet address
    fn get_wallet_address(
        &self,
        version: TokenWalletVersion,
        owner: &MsgAddressInt,
    ) -> Result<MsgAddressInt> {
        let mut function = abi::FunctionBuilder::new("getWalletAddress")
            .default_headers()
            .in_arg("wallet_public_key_", ton_abi::ParamType::Uint(256))
            .in_arg("owner_address_", ton_abi::ParamType::Address)
            .out_arg("address", ton_abi::ParamType::Address);

        let mut inputs = adjust_responsible(&mut function, version);
        inputs.push(ton_abi::Token::new(
            "wallet_public_key_",
            abi::BigUint256(Default::default()).token_value(),
        ));
        inputs.push(ton_abi::Token::new("owner_address_", owner.token_value()));

        let address = self
            .0
            .run_local(&function.build(), &inputs)?
            .into_parser()
            .parse_next()?;

        Ok(address)
    }

    /// Tries to guess version and retrieve details
    fn guess_details(&self) -> Result<RootTokenContractDetails> {
        // check Tip3v3+ version via direct call
        match get_version_direct(self.0) {
            Ok(GotVersion::Known(version)) => return self.get_details(version),
            Ok(GotVersion::Unknown) => return Err(TokenWalletError::UnknownVersion.into()),
            _ => {} // fallback to Tip3v1 or Tip3v2
        };

        for &version in &[TokenWalletVersion::Tip3v2, TokenWalletVersion::Tip3v1] {
            if let Ok(details) = self.get_details(version) {
                return Ok(details);
            }
        }

        Err(TokenWalletError::UnknownVersion.into())
    }

    /// Retrieve details using specified version
    fn get_details(&self, version: TokenWalletVersion) -> Result<RootTokenContractDetails> {
        let mut details_abi = TupleBuilder::new()
            .arg("name", ton_abi::ParamType::Bytes)
            .arg("symbol", ton_abi::ParamType::Bytes)
            .arg("decimals", ton_abi::ParamType::Uint(8))
            .arg("wallet_code", ton_abi::ParamType::Cell)
            .arg("root_public_key", ton_abi::ParamType::Uint(256))
            .arg("root_owner_address", ton_abi::ParamType::Address)
            .arg("total_supply", ton_abi::ParamType::Uint(128));

        if version == TokenWalletVersion::Tip3v1 {
            details_abi = details_abi
                .arg("start_gas_balance", ton_abi::ParamType::Uint(128))
                .arg("paused", ton_abi::ParamType::Bool);
        }

        let mut function = abi::FunctionBuilder::new("getDetails")
            .default_headers()
            .out_arg("value0", details_abi.build());

        let inputs = adjust_responsible(&mut function, version);

        let details: BriefRootTokenContractDetails = self
            .0
            .run_local(&function.build(), &inputs)?
            .into_parser()
            .parse_next()?;

        Ok(details.extend(version))
    }
}

impl abi::ParseToken<BriefRootTokenContractDetails> for ton_abi::TokenValue {
    fn try_parse(self) -> abi::ContractResult<BriefRootTokenContractDetails> {
        let mut tuple = match self {
            ton_abi::TokenValue::Tuple(tokens) => tokens.into_parser(),
            _ => return Err(abi::ParserError::InvalidAbi),
        };

        let name = tuple.parse_next()?;
        let symbol = tuple.parse_next()?;
        let decimals = tuple.parse_next()?;
        let _wallet_code: ton_types::Cell = tuple.parse_next()?;
        let _root_public_key: ton_types::UInt256 = tuple.parse_next()?;
        let owner_address = tuple.parse_next()?;

        Ok(BriefRootTokenContractDetails {
            name,
            symbol,
            decimals,
            owner_address,
        })
    }
}

struct BriefRootTokenContractDetails {
    name: String,
    symbol: String,
    decimals: u8,
    owner_address: MsgAddressInt,
}

impl BriefRootTokenContractDetails {
    pub fn extend(self, version: TokenWalletVersion) -> RootTokenContractDetails {
        RootTokenContractDetails {
            version,
            name: self.name,
            symbol: self.symbol,
            decimals: self.decimals,
            owner_address: self.owner_address,
        }
    }
}

struct TokenWalletContractState<'a>(&'a ExistingContract);

impl<'a> TokenWalletContractState<'a> {
    fn get_balance(&self, version: TokenWalletVersion) -> Result<BigUint> {
        let mut function = abi::FunctionBuilder::new("balance")
            .default_headers()
            .out_arg("value0", ton_abi::ParamType::Uint(128));

        let inputs = adjust_responsible(&mut function, version);

        let balance = self
            .0
            .run_local(&function.build(), &inputs)?
            .into_parser()
            .parse_next()?;

        Ok(balance)
    }

    fn get_details(&self, version: TokenWalletVersion) -> Result<TokenWalletDetails> {
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

        let details = self
            .0
            .run_local(&function.build(), &inputs)?
            .into_parser()
            .parse_next()?;

        Ok(details)
    }

    fn get_version(&self) -> Result<TokenWalletVersion> {
        // check Tip3v3+ version via direct call
        match get_version_direct(self.0) {
            Ok(GotVersion::Known(version)) => return Ok(version),
            Ok(GotVersion::Unknown) => return Err(TokenWalletError::UnknownVersion.into()),
            _ => {} // fallback to Tip3v1 or Tip3v2
        };

        for &version in &[TokenWalletVersion::Tip3v2, TokenWalletVersion::Tip3v1] {
            if self.get_details(version).is_ok() {
                return Ok(version);
            }
        }

        Err(TokenWalletError::UnknownVersion.into())
    }
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

struct RootMetaContractState<'a>(&'a ExistingContract);

impl<'a> RootMetaContractState<'a> {
    fn get_details(&self) -> Result<RootMetaDetails> {
        let function = abi::FunctionBuilder::new("getMetaByKey")
            .header("time", ton_abi::ParamType::Time)
            .in_arg("key", ton_abi::ParamType::Uint(16))
            .out_arg("value", ton_abi::ParamType::Cell)
            .build();

        let value: ton_types::Cell = self
            .0
            .run_local(&function, &[0u16.token_value().named("key")])?
            .into_parser()
            .parse_next()?;

        let proxy_address = MsgAddressInt::construct_from_cell(value).convert()?;

        Ok(RootMetaDetails { proxy_address })
    }
}

struct RootMetaDetails {
    proxy_address: MsgAddressInt,
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

fn get_version_direct(contract: &ExistingContract) -> Result<GotVersion> {
    let function = abi::FunctionBuilder::new_responsible("getVersion")
        .default_headers()
        .out_arg("value0", ton_abi::ParamType::Uint(32))
        .build();

    let version: u32 = contract
        .run_local(&function, &[abi::answer_id()])?
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

fn compute_root_meta_address(root_token_contract: &MsgAddressInt) -> MsgAddressInt {
    let mut code = contracts::code::root_meta().into();
    let mut state_init = ton_block::StateInit::construct_from(&mut code).trust_me();

    state_init.data = {
        let data: ton_types::SliceData = state_init.data.take().unwrap_or_default().into();
        let mut map = ton_types::HashmapE::with_hashmap(
            ton_abi::Contract::DATA_MAP_KEYLEN,
            data.reference_opt(0),
        );

        let mut value = ton_types::BuilderData::new();
        root_token_contract.write_to(&mut value).trust_me();

        map.set(1u64.write_to_new_cell().trust_me().into(), &value.into())
            .trust_me();

        Some(map.write_to_new_cell().trust_me().into())
    };

    let hash = state_init.hash().trust_me();

    MsgAddressInt::AddrStd(ton_block::MsgAddrStd {
        anycast: None,
        workchain_id: 0,
        address: hash.into(),
    })
}

trait ExistingContractExt {
    fn run_local(
        &self,
        function: &ton_abi::Function,
        input: &[ton_abi::Token],
    ) -> Result<Vec<ton_abi::Token>>;
}

impl ExistingContractExt for ExistingContract {
    fn run_local(
        &self,
        function: &ton_abi::Function,
        input: &[ton_abi::Token],
    ) -> Result<Vec<ton_abi::Token>> {
        function.run_local(
            self.account.clone(),
            self.timings,
            &self.last_transaction_id,
            input,
        )
    }
}

#[derive(thiserror::Error, Debug)]
enum TokenWalletError {
    #[error("Unknown version")]
    UnknownVersion,
    #[error("Invalid root token contract")]
    InvalidRootTokenContract,
    #[error("Invalid root meta contract")]
    InvalidRootMetaContract,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn convert_address(addr: &str) -> MsgAddressInt {
        MsgAddressInt::from_str(addr).unwrap()
    }

    fn prepare_contract(data: &str) -> ExistingContract {
        let account = match ton_block::Account::construct_from_base64(data).unwrap() {
            ton_block::Account::Account(stuff) => stuff,
            _ => unreachable!(),
        };
        ExistingContract {
            account,
            timings: Default::default(),
            last_transaction_id: LastTransactionId::Inexact { latest_lt: 0 },
        }
    }

    fn root_token_contract(version: TokenWalletVersion) -> ExistingContract {
        let data = match version {
            TokenWalletVersion::Tip3v1 => ROOT_TOKEN_STATE_TIP3_V1,
            TokenWalletVersion::Tip3v2 => ROOT_TOKEN_STATE_TIP3_V2,
            TokenWalletVersion::Tip3v3 => ROOT_TOKEN_STATE_TIP3_V3,
        };
        prepare_contract(data)
    }

    const ROOT_TOKEN_STATE_TIP3_V1: &str = "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";
    const ROOT_TOKEN_STATE_TIP3_V2: &str = "te6ccgECqgEAJx8AAnPADOcXDcMUS0fCqCF6CrhQZyn2MQ4TEQF7IDBOoLlzsWDTVMBJhYMDGXLYAAAtGVVEuxVAlTMBYRNAYQEE/TUTNWvFNVDdzZ2+7uqpDFQN/63Zo9m5KasOhXo/ywmiAAABeFFB4DCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4MAAAAAAAAAAAAAAAA5jmPvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyMrO1NaBgX14CAib/APSkICLAAZL0oOGK7VNYMPShCQMBCvSkIPShBAIJnwAAAAMHBQEBIAYA/O1E0NP/0z/TANX6QNN/0wfTB9MH0wfTB9MH0wfTB9MH0wfTB9MH0wf4f/h++H34fPh7+Hr4efh4+Hf4dvh1+HT4c/hy+G/4bdWAIPhg+kDU0//Tf/QEASBuldDTf28C3/hw0wfXCgCAIfhg+HH4bvhs+Gv4an/4Yfhm+GP4YgHvPhCyMv/+EPPCz/4Rs8LAMj4TfhP+FL4U/hU+FX4VvhX+Fj4Wfha+Fv4XPhd+F74X17wzst/ywfLB8sHywfLB8sHywfLB8sHywfLB8sHywfOyIAg+EABzvhK+Ev4TPhO+FD4UYAh+EBegM8RzxHOzMv/y38BIG6zgCABGjhXIAW8iyCLPC38hzxYxMc8XAc+DzxGTMM+B4ssHygDJ7VQCASANCgFi/3+NCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAT4aSHtRNAg10nCAQsB+o570//TP9MA1fpA03/TB9MH0wfTB9MH0wfTB9MH0wfTB9MH0wfTB/h/+H74ffh8+Hv4evh5+Hj4d/h2+HX4dPhz+HL4b/ht1YAg+GD6QNTT/9N/9AQBIG6V0NN/bwLf+HDTB9cKAIAh+GD4cfhu+Gz4a/hqf/hh+Gb4Y/hiDAHkjoDi0wABjh2BAgDXGCD5AQHTAAGU0/8DAZMC+ELiIPhl+RDyqJXTAAHyeuLTPwGOHvhDIbkgnzAg+COBA+iogggbd0Cgud6S+GPggDTyNNjTHwH4I7zyudMfIcEDIoIQ/////byxkVvgAfAB+EdukTDeGQIBICMOAgEgHA8CASAUEAIBSBMRAfm0tmb7/CC3SXgB72j8KJBggUmYQDJvfCb9ITeJ64X/4YAQS5h8Jvwk44LvEEcKGHwmYYAQThh8JnwikDdJGDhvXW9v+Xp8Jv0hN4nrhf/hgEcNfCd8E7eIODRTfbBKtFN/MBjv0Nq/2wS5fYFJfABxNvw4fCb9ITeJ64X/wBIAOo4V+EnIz4WIzoBtz0DPgc+ByYEAgPsA3vACf/hnANG093Q6/CC3SXgB730gyupo6H0gb+uGAErqaOhpAG/o/CiQYIFJmEAyb3wm/SE3ieuF/+GAEEuYfCb8JOOC7xBHChh8JmGAEE4YfCZ8IpA3SRg4b11vb/l6fAAQ/D+QQBD8MC34AT/8M8ABD7kWq+f/CC3QFQHyjoDe+Ebyc3H4ZtH4TMMAIJww+E36Qm8T1wv/wADeII4UMPhMwAAgnDD4TfpCbxPXC//DAN7f8uBk+AD4TfpCbxPXC/+OLfhNyM+FiM6NA8icQAAAAAAAAAAAAAAAAAHPFs+Bz4HPkSFO7N74Ss8WyXH7AN7wAn/4ZxYBEO1E0CDXScIBFwH6jnvT/9M/0wDV+kDTf9MH0wfTB9MH0wfTB9MH0wfTB9MH0wfTB9MH+H/4fvh9+Hz4e/h6+Hn4ePh3+Hb4dfh0+HP4cvhv+G3VgCD4YPpA1NP/03/0BAEgbpXQ039vAt/4cNMH1woAgCH4YPhx+G74bPhr+Gp/+GH4Zvhj+GIYAQaOgOIZAf70BXEhgED0Do4kjQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE3/hqciGAQPQPksjJ3/hrcyGAQPQOk9cL/5Fw4vhsdCGAQPQOjiSNCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATf+G1w+G5wGgH8+G9t+HBw+HFw+HJw+HNw+HRw+HVw+HZw+Hdw+Hhw+Hlw+Hpw+Htw+Hxw+H1w+H6NCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAT4f40IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIAg+GBwGwC8gCH4YHABgED0DvK91wv/+GJw+GNw+GZ/+GGCCvrwgPhugGT4cYBl+HKAZvhzgGf4dIBo+HWAafh2gGr4d4Br+HiAbPh5gG34eoBu+HuAb/h8gHD4fYBx+H5/gCH4YAEJur8WDigdAfr4QW6S8APe+kGV1NHQ+kDf1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/XDACV1NHQ0gDf1NH4USDBApMwgGTe+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8vQkwgDy4GT4UiDBAh4BfJMwgGTeJfhPu/L0+F0gwQKTMIBk3ib6Qm8T1wv/wwDy9PhdIMECkzCAZN4m+CjHBbPy9PhN+kJvE9cL/8MAHwL8joCOd/hbIMECkzCAZN74J28QJbzy9PhbIMECkzCAZN4k+E688vT4ACT4TwGhtX/4byIg+kJvE9cL/5P4KDHfJCd/yM+FgMoAc89AzgH6AoBpz0DPgc+DyM+QY0hcCifPC3/4TM8L//hNzxYizxYkzwoAI88Uzclx+wAw4l8GISAACvACf/hnAfr4TvgnbxBwaKb7YJVopv5gMd+htX+2CfhbIMECkzCAZN74J28QIvhOoLV/vPL0IHL7AiX4TwGhtX/4byMg+kJvE9cL/5P4TTHfJ3/Iz4WAygBzz0DOgG3PQM+Bz4PIz5BjSFwKKM8Lf/hMzwv/+E3PFiLPFiXPCgAkzxTNySIADIEAgPsAWwIBIDskAgEgMiUCA33oKyYBB6yzyownAfz4QW6S8APe+kGV1NHQ+kDf1w1/ldTR0NN/3/pBldTR0PpA39cMAJXU0dDSAN/U0fhYIMECkzCAZN74UG6z8vT4WSDBApMwgGTe+En4UCBu8n9vEccF8vT4WiDBApMwgGTeJPhQIG7yf28Qu/L0+FIgwQKTMIBk3iT4T7vy9CMoAeLCAPLgZPhdIMECkzCAZN4l+CjHBbPy9PhN+kJvE9cL/8MAjk34TvgnbxBwaKb7YJVopv5gMd+htX+2CfhbIMECkzCAZN74J28QIvhOoLV/vPL0IHL7AvhO+CdvEHBopvtglWim/mAx36G1f7YJcvsCMCkB/I4x+FsgwQKTMIBk3nBopvtglWim/mAx3/hOvPL0+CdvEHBopvtglWim/mAx36G1f3L7AuIj+E8BobV/+G/4UCBu8n9vECShtX/4UCBu8n9vEW8C+HAkf8jPhYDKAHPPQM6Abc9Az4HPg8jPkGNIXAolzwt/+EzPC//4Tc8WJCoALs8WI88KACLPFM3JgQCA+wBfBfACf/hnAeGsho1fwgt0l4Ae9rhv/K6mjoaf/v/SDK6mjofSBv64a/yupo6Gm/7+uGv8rqaOhpv+/rhr/K6mjoab/v/SDK6mjofSBv64YASupo6GkAb+po/CiQYIFJmEAyb3wm/SE3ieuF/+GAEEuYfCb8JOOC7xBCwB2o4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8vQlwgDy4GT4UiDBApMwgGTeJvhPu/L0+FwgwQKTMIBk3if6Qm8T1wv/wwAglDAowADeII4SMCf6Qm8T1wv/wAAglDAowwDe3/L0+E36Qm8T1wv/wwAtAf6OSfhO+CdvEHBopvtglWim/mAx36G1f7YJ+FsgwQKTMIBk3vgnbxAi+E6gtX8ooLV/vPL0+F0gwQKTMIBk3ij4TccFs/L0IHL7AjCOL/hbIMECkzCAZN74J28QJiagtX+88vT4WyDBApMwgGTeJPhOvPL0J/hMvfLgZPgA4m0oLgGUyMv/cFiAQPRD+EpxWIBA9Bb4S3JYgED0FyjIy/9zWIBA9EMndFiAQPQWyPQAyfhLyM+EgPQA9ADPgckg+QDIz4oAQMv/ydAmwgAvAZSOOyEg+QD4KPpCbxLIz4ZAygfL/8nQKCHIz4WIzgH6AoBpz0DPg8+DIs8Uz4PIz5Gi1Xz+yc8UyXH7ADEw3iT4TfpCbxPXC//DADABoo5PKPhPAaG1f/hvIPpCbxPXC/+T+E0x3yF/yM+FgMoAc89AzoBtz0DPgc+DyM+QY0hcCirPC3/4TM8L//hNzxYizxYmzwoAJc8UzcmBAID7ADEAuo5RKPhPAaG1f/hvIPpCbxPXC/+T+Cgx3yYif8jPhYDKAHPPQM4B+gKAac9Az4HPg8jPkGNIXAoqzwt/+EzPC//4Tc8WIs8WJs8KACXPFM3JcfsA4l8DXwjwAn/4ZwIBWDQzAPe1wrhzfCC3SXgB72j8KDdZy3woEDd5P8cTuEaEMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjeBcRDgf8cWEehpgP0gGBjkZ8OQZ0AwZ6BnwOfA58lfCuHNELeRLBFnhb+Q54sYmOS4/YBvGEl4AW8//DPAAgFmOjUBB68SJfo2Afz4QW6S8APe+kGV1NHQ+kDf+kGV1NHQ+kDf1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/XDACV1NHQ0gDf1NH4USDBApMwgGTe+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8vT4XSA3AWzBApMwgGTeJvpCbxPXC//DAPL0JMIA8uBk+F0gwQKTMIBk3icnxwWz8vQi+E36Qm8T1wv/wwA4AeaOcfhO+CdvEHBopvtglWim/mAx36G1f7YJ+FsgwQKTMIBk3vgnbxAi+E5yqLV/oLV/vPL0IHL7AiH6Qm8T1wv/k/hNMt8oyM+FiM6Abc9Az4HPg8jPkP1Z5UYpzxYozwt/I88WJc8KACTPFM3JgQCA+wAwOQDejmT4WyDBApMwgGTe+CdvECa88vT4WyDBApMwgGTeJfhOcqi1f7zy9PgAIPpCbxPXC/+T+Cgx3yQoyM+FiM4B+gKAac9Az4HPg8jPkP1Z5UYozxYnzwt/Is8WJM8KACPPFM3JcfsA4jBfB/ACf/hnAOmu+bib4QW6S8APe0fhK+Ev4TPhN+E/4X4Ag+ECAIfhAbwghwP+ORSPQ0wH6QDAxyM+HIM6AYM9Az4HPg8jPkqT5uJoibyhVByjPFifPFCbPC/8lzxYkzwt/yCTPFiPPFiLPCgBsgs3NyXH7AN4wkvAC3n/4Z4CASBHPAIBIEI9AQm2NIXAoD4B/vhBbpLwA97XDX+V1NHQ03/f1w3/ldTR0NP/3/pBldTR0PpA3/pBldTR0PpA39cMAJXU0dDSAN/U0fheIMECkzCAZN4igCH4QLEgnDD4X/pCbxPXC//AAN/y9CQkbSLIy/9wWIBA9EP4SnFYgED0FvhLcliAQPQXIsjL/3NYgEA/Ab70QyF0WIBA9BbI9ADJ+EvIz4SA9AD0AM+BySD5AMjPigBAy//J0ANfA/hUIMECkzCAZN74SSLHBfL0+F0gwQKTMIBk3iX4TccFsyCVMCb4TL3f8vT4TfpCbxPXC//DAEABxI4u+E74J28QcGim+2CVaKb+YDHfobV/tgn4WyDBApMwgGTe+CdvECK88vQgcvsCMI4W+CdvEHBopvtglWim/mAx36G1f3L7AuIm+E8BoLV/+G8iIJww+F/6Qm8T1wv/wwDeQQDGjkP4X8jPhYjOgG3PQM+Bz4PIz5FlBH7m+CjPFvhKzxYozwt/J88L/8gnzxb4Sc8WJs8WyPhPzwt/Jc8Uzc3NyYEAgPsAjhQjyM+FiM6Abc9Az4HPgcmBAID7AOJfB/ACf/hnAQm2EfJBIEMB/PhBbpLwA97XDX+V1NHQ03/f1w1/ldTR0NN/3/pBldTR0PpA3/pBldTR0PpA39TR+FEgwQKTMIBk3vhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/L0JMIA8uBk+FIgwQKTMIBk3iX4T7vy9EQBrPhbIMECkzCAZN74TfpCbxPXC//DACCfMHBopvtglWim/mAx38IA3iCOHTD4TfpCbxPXC//AACCeMCT4J28QuyCUMCTCAN7e3/L0IvhN+kJvE9cL/8MARQHajmv4TvgnbxBwaKb7YJVopv5gMd+htX+2CXL7AiX4TwGhtX/4byD6Qm8T1wv/k/hNMd/4Sn/Iz4WAygBzz0DOgG3PQM+Bz4PIz5C4oiKqJ88Lf/hMzwv/+E3PFiLPFsglzxYkzxTNzcmBAID7AEYAwI5V+AAl+E8BobV/+G8g+kJvE9cL/5P4KDHfJPhKf8jPhYDKAHPPQM4B+gKAac9Az4HPg8jPkLiiIqonzwt/+EzPC//4Tc8WIs8WyCXPFiTPFM3NyXH7AOIwXwXwAn/4ZwIBIFBIAgEgT0kCASBMSgEIswJYqksA+vhBbpLwA976QZXU0dD6QN/R+FEgwQKTMIBk3vhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/L0+E/AAPLgZPgAIMjPhQjOjQPID6AAAAAAAAAAAAAAAAABzxbPgc+ByYEAoPsAMPACf/hnAQiyL/INTQH++EFukvAD3tcNf5XU0dDTf9/6QZXU0dD6QN/6QZXU0dD6QN/U0fhTIMECkzCAZN74SvhJxwXy9CPCAPLgZPhSIMECkzCAZN4k+E+78vT4J28QcGim+2CVaKb+YDHfobV/cvsCI/hPAaG1f/hv+Ep/yM+FgMoAc89AzoBtz0DPgU4AXs+DyM+QuKIiqiXPC3/4TM8L//hNzxYkzxbIJM8WI88Uzc3JgQCA+wBfBPACf/hnAHO1n+er/CC3SXgB72uGv8rqaOhpv+/o/CmQYIFJmEAyb3wlfCTjgvl6fAAQfCeA0Fq//DeYeAE//DPAAgEgVFECASBTUgBesm23iPAD+E/Ii9wAAAAAAAAAAAAAAAAgzxbPgc+Bz5IZtt4iIc8Lf8lx+wB/+GcAtrPFAA/4QW6S8APe+kGV1NHQ+kDf0fhRIMECkzCAZN74TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y9PgAIIAg+GAw8AJ/+GcCASBYVQEIsyHRc1YB/vhBbpLwA976QZXU0dD6QN/XDX+V1NHQ03/f1w1/ldTR0NN/39H4USDBApMwgGTe+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8vT4VyDBApMwgGTeIsAAIJYw+FBus7Pf8vT4TfpCbxPXC/9XANTDAI4a+E74J28QcGim+2CVaKb+YDHfobV/tgly+wKS+ADi+FBus44S+FAgbvJ/bxAiupYgI28C+HDeliAjbwL4cOL4TfpCbxPXC/+OFfhJyM+FiM6Abc9Az4HPgcmBAID7AN5fA/ACf/hnARzZcCLQ0wP6QDD4aak4AFkBSI6A4CHHANwh0x8h3SHBAyKCEP////28sZFb4AHwAfhHbpEw3loBLiHWHzFx8AHwA/gAINMfMiCCEBjSFwK6WwG0joCOUiCCEC4oiKq6jkch038z+E8BoLV/+G/4TfpCbxPXC/+OL/hO+CdvEHBopvtglWim/mAx36G1f7YJcvsC+E3Iz4WIzoBtz0DPgc+ByYEAgPsA3t7iW/ACXAHQIdN/MyD4TwGgtX/4b4Ag+ED6Qm8T1wv/wwCOTPgnbxBwaKb7YJVopv5gMd+htX9y+wKAIPhAyM+FiM6Abc9Az4HPg8jPkOoV2UL4KM8W+ErPFiLPC3/I+EnPFvhPzwt/zc3JgQCA+wBdAH6OO/hN+kJvE9cL/44v+E74J28QcGim+2CVaKb+YDHfobV/tgly+wL4TcjPhYjOgG3PQM+Bz4HJgQCA+wDe4jAACFVTRFQADFRldGhlcgBjgAvpSKEmcdsAU50DME0ul92s65jErkbosgMW7ZfKyelfAAAAAAAAAAAAAAAAScyX5/ACJv8A9KQgIsABkvSg4YrtU1gw9KFmYgEK9KQg9KFjAgPPQGVkAJ1O1E0NP/0z/TANX6QNcLf/hy+HHT/9TU0wfU03/T/9MH0wfTB9MH0wfXCgD4ePh3+Hb4dfh0+HP4cPhv+G74bfhs+Gv4an/4Yfhm+GP4YoAKFfhCyMv/+EPPCz/4Rs8LAMj4UfhSAs7Lf/hK+Ev4TPhN+E74T/hQ+FP4VPhV+Fb4V/hYXtDPEcv/zMzLB8zLf8v/ywfLB8sHywfLB8oAye1UgCASBpZwH8/3+NCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAT4aSHtRNAg10nCAY5L0//TP9MA1fpA1wt/+HL4cdP/1NTTB9TTf9P/0wfTB9MH0wfTB9cKAPh4+Hf4dvh1+HT4c/hw+G/4bvht+Gz4a/hqf/hh+Gb4Y/hiaAHkjoDi0wABjh2BAgDXGCD5AQHTAAGU0/8DAZMC+ELiIPhl+RDyqJXTAAHyeuLTPwGOHvhDIbkgnzAg+COBA+iogggbd0Cgud6S+GPggDTyNNjTHwH4I7zyudMfIcEDIoIQ/////byxkVvgAfAB+EdukTDepwIBIIhqAgEgfGsCASBzbAIBIG5tAF22YWz9PAC+EvIi9wAAAAAAAAAAAAAAAAgzxbPgc+Bz5PmFs/SIc8UyXH7AH/4Z4AIDeSBwbwBdrXSb/4AXwpZEXuAAAAAAAAAAAAAAAAEGeLZ8DnwOfJ5N0m/xDnhb/kuP2AP/wzwBB63uJnRxAf74QW6S8ALe1w1/ldTR0NN/3/pBldTR0PpA39H4UyDBApMwgGTe+FH6Qm8T1wv/wwAglzD4UfhJxwXeII4UMPhQwwAgnDD4UPhFIG6SMHDeut7f8vT4ACDIz4WIzo0EDmJaAAAAAAAAAAAAAAAAAAHPFs+Bz4HPkCz/PV4izwt/cgAmyXH7ACH4TwGgtX/4b1vwAX/4ZwIBIHd0AQm2VUvMIHUB/vhBbpLwAt7XDf+V1NHQ0//f+kGV1NHQ+kDf0fhWIMECkzCAZN4h+kJvE9cL/8MAIJQwIsAA3iCOEjAh+kJvE9cL/8AAIJQwIsMA3t/y9CEhbSLIy/9wWIBA9EP4KHFYgED0FvhOcliAQPQXIsjL/3NYgED0QyF0WIBA9BbI9AB2AJ7J+E7Iz4SA9AD0AM+BySD5AMjPigBAy//J0ANfAzExIcD/jiIj0NMB+kAwMcjPhyDOgGDPQM+Bz4HPk6VUvMIhzxbJcfsA3jCS8AHef/hnAQm3iEcb4HgB+PhBbpLwAt7XDX+V1NHQ03/f1w1/ldTR0NN/39cN/5XU0dDT/9/6QZXU0dD6QN/6QZXU0dD6QN/R+FMgwQKTMIBk3vhR+kJvE9cL/8MAIJcw+FH4SccF3iCOFDD4UMMAIJww+FD4RSBukjBw3rre3/L0JHC+8uBk+FYgwQJ5Af6TMIBk3iL6Qm8T1wv/wwAglDAjwADeII4SMCL6Qm8T1wv/wAAglDAjwwDe3/L0+FH6Qm8T1wv/wACS+ACOGvhS+CdvEHBopvtglWim/mAx36G1f7YJcvsC4m0jyMv/cFiAQPRD+ChxWIBA9Bb4TnJYgED0FyPIy/9zWIBA9EMiegH+dFiAQPQWyPQAyfhOyM+EgPQA9ADPgckg+QDIz4oAQMv/ydAlIcjPhYjOAfoCgGnPQM+Dz4MizxTPgc+RotV8/slx+wAxIMjPhYjOjQQOYloAAAAAAAAAAAAAAAAAAc8Wz4HPgc+QLP89XibPC3/JcfsAJfhPAaC1f/hv+FH6QnsA4G8T1wv/jjgh+kJvE9cL/8MAjhQhyM+FiM6Abc9Az4HPgcmBAID7AI4V+EnIz4WIzoBtz0DPgc+ByYEAgPsA4t4mwP+OIijQ0wH6QDAxyM+HIM6AYM9Az4HPgc+TmIRxviHPFslx+wDeMF8F8AF/+GcCASCFfQICcoF+AQexZ1P3fwH6+EFukvAC3tcN/5XU0dDT/9/6QZXU0dD6QN/6QZXU0dD6QN/R+CdvEHBopvtglWim/mAx36G1f3L7AiIibSLIy/9wWIBA9EP4KHFYgED0FvhOcliAQPQXIsjL/3NYgED0QyF0WIBA9BbI9ADJ+E7Iz4SA9AD0AM+BySD5AMiAAHDPigBAy//J0ANfAyHIz4WIzoBtz0DPgc+DyM+QRc3lciLPFiXPC/8kzxbNyYEAgPsAXwTwAX/4ZwEHsFYs5YIB/PhBbpLwAt7XDX+V1NHQ03/f1w3/ldTR0NP/3/pBldTR0PpA3/pBldTR0PpA39H4ViDBApMwgGTeIvpCbxPXC//DACCUMCPAAN4gjhIwIvpCbxPXC//AACCUMCPDAN7f8vT4J28QcGim+2CVaKb+YDHfobV/cvsCbSPIy/9wWIMB3IBA9EP4KHFYgED0FvhOcliAQPQXI8jL/3NYgED0QyJ0WIBA9BbI9ADJ+E7Iz4SA9AD0AM+BySD5AMjPigBAy//J0CUhyM+FiM4B+gKAac9Az4PPgyLPFM+Bz5Gi1Xz+yXH7ADEh+kJvE9cL/8MAhAC+jhQhyM+FiM6Abc9Az4HPgcmBAID7AI4V+EnIz4WIzoBtz0DPgc+ByYEAgPsA4gRfBCHA/44iI9DTAfpAMDHIz4cgzoBgz0DPgc+Bz5NQrFnKIc8WyXH7AN4w8AF/+GcCASCHhgBftyrlKjwAvhPyIvcAAAAAAAAAAAAAAAAIM8Wz4HPgc+TMq5SoiHPC3/JcfsAf/hngAF23bO9/fAC+EzIi9wAAAAAAAAAAAAAAAAgzxbPgc+Bz5MWzvf2Ic8UyXH7AH/4Z4AIBIJaJAgEgjooCASCNiwHptgoJhr4QW6S8ALe1w3/ldTR0NP/3/pBldTR0PpA39H4UyDBApMwgGTe+FH6Qm8T1wv/wwAglzD4UfhJxwXeII4UMPhQwwAgnDD4UPhFIG6SMHDeut7f8vT4ViDBApMwgGTeIsMAIJswIfpCbxPXC//AAN4ggjABKjhIwIsAAIJswIfpCbxPXC//DAN7f8vT4ACH4cCD4cVvwAX/4ZwBftiNZtHwAvhYyIvcAAAAAAAAAAAAAAAAIM8Wz4HPgc+SwjWbRiHPCgDJcfsAf/hngAgEgk48BCbeKIiqgkAH++EFukvAC3tcNf5XU0dDTf9/XDf+V1NHQ0//f+kGV1NHQ+kDf+kGV1NHQ+kDf+kGV1NHQ+kDf1NH4VyDBApMwgGTe+Fiz8vQkJG0iyMv/cFiAQPRD+ChxWIBA9Bb4TnJYgED0FyLIy/9zWIBA9EMhdFiAQPQWyPQAyfhOyM+EgJEBzPQA9ADPgckg+QDIz4oAQMv/ydADXwP4VSDBApMwgGTe+EkixwXy9PgnbxBwaKb7YJVopv5gMd+htX9y+wIm+E8BobV/+G8i+kJvE9cL/8AAjhQjyM+FiM6Abc9Az4HPgcmBAID7AJIAeI4yIsjPhYjOgG3PQM+Bz4PIz5DzJED6KM8LfyPPFCfPC/8mzxYizxbIJs8Wzc3JgQCA+wDiXwfwAX/4ZwIBSJWUAFyylxn38AL4TsiL3AAAAAAAAAAAAAAAACDPFs+Bz4HPkopcZ94hzxTJcfsAf/hnALay68dt+EFukvAC3vpBldTR0PpA39H4UyDBApMwgGTe+FH6Qm8T1wv/wwAglzD4UfhJxwXe8vT4UnL7AiDIz4WIzoBtz0DPgc+Bz5A7trPyyYEAgPsAMPABf/hnAgEgnJcCASCbmAEJt34aKmCZAf74QW6S8ALe1w1/ldTR0NN/3/pBldTR0PpA3/pBldTR0PpA3/pBldTR0PpA39TR+FMgwQKTMIBk3vhR+kJvE9cL/8MAIJcw+FH4SccF3vL0+CdvEHBopvtglWim/mAx36G1f3L7AiJwJW0iyMv/cFiAQPRD+ChxWIBA9Bb4TnJYmgDkgED0FyLIy/9zWIBA9EMhdFiAQPQWyPQAyfhOyM+EgPQA9ADPgckg+QDIz4oAQMv/ydADXwMk+kJvE9cL/5IlMt8gyM+FiM6Abc9Az4HPg8jPkDC/yDYozwt/I88WJc8WJM8UzcmBAID7AFtfBfABf/hnAF+3QBbB/AC+E3Ii9wAAAAAAAAAAAAAAAAgzxbPgc+Bz5JUAWweIc8LB8lx+wB/+GeACASCenQClt1a/HL4QW6S8ALe0gDR+FMgwQKTMIBk3vhR+kJvE9cL/8MAIJcw+FH4SccF3iCOFDD4UMMAIJww+FD4RSBukjBw3rre3/L0+AAg+Hgw8AF/+GeACASCgnwDXtX4Vfvwgt0l4AW9o/CX8Jnwm/Cd8KHwo/Ce3g5Dgf8cgkehpgP0gGBjkZ8OQZ0AwZ6BnwOfB5GfJDfhV+xE3k6qDE+eKE2eKEueFg5JnihHnhf+RZ4sQ54W/g6+D5uS4/YBvGEl4AO8//DPAAgFIqaECAW6jogCrq1Gmb4QW6S8ALe0z/6QZXU0dD6QN/R+CdvEHBopvtglWim/mAx36G1f3L7AiDIz4WIzoBtz0DPgc+Bz5HOG8OiIs8LP/hYzwoAyYEAgPsAW/ABf/hngBDatT0d+EFuikAdaOgN74RvJzcfhm1w3/ldTR0NP/3/pBldTR0PpA39H4ViDBApMwgGTeIsMAIJswIfpCbxPXC//AAN4gjhIwIsAAIJswIfpCbxPXC//DAN7f8vT4ACH4cCD4cXD4b3D4ePgnbxD4clvwAX/4Z6UBqu1E0CDXScIBjkvT/9M/0wDV+kDXC3/4cvhx0//U1NMH1NN/0//TB9MH0wfTB9MH1woA+Hj4d/h2+HX4dPhz+HD4b/hu+G34bPhr+Gp/+GH4Zvhj+GKmAQaOgOKnAf70BXEhgED0DpPXC/+RcOL4anIhgED0D5LIyd/4a3MhgED0D5LIyd/4bHQhgED0DpPXCweRcOL4bXUhgED0D5LIyd/4bnD4b3D4cI0IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPhxcPhycPhzcPh0cPh1cPh2qABgcPh3cPh4cAGAQPQO8r3XC//4YnD4Y3D4Zn/4YYBk+HOAZfh0gGf4dYBq+HaAa/h3ALjYcCLQ0wP6QDD4aak4AI4qIdYfMXHwAfAC+AAg0x8yIIIQCz/PV7qeIdN/MyD4TwGhtX/4bzDeW/AB4CHHANwh0x8h3SHBAyKCEP////28sZFb4AHwAfhHbpEw3g==";
    const ROOT_TOKEN_STATE_TIP3_V3: &str = "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";

    fn token_wallet_contract(version: TokenWalletVersion) -> ExistingContract {
        let data = match version {
            TokenWalletVersion::Tip3v1 => TOKEN_WALLET_STATE_TIP3_V1,
            TokenWalletVersion::Tip3v2 => TOKEN_WALLET_STATE_TIP3_V2,
            TokenWalletVersion::Tip3v3 => TOKEN_WALLET_STATE_TIP3_V3,
        };
        prepare_contract(data)
    }

    const TOKEN_WALLET_STATE_TIP3_V1: &str = "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";
    const TOKEN_WALLET_STATE_TIP3_V2: &str = "te6ccgECYAEAGBsAAm/ADwMajtFO0E52HsAmDVq4kH5N4AZDaeUQD+cUWUV2AkJSwK1yAwNY5uAAAC3oGrkWEQC+vCATQAQBA/UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAznFw3DFEtHwqghegq4UGcp9jEOExEBeyAwTqC5c7Fg0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL68IAyYDAgQAQ4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAv4AVJCimjkbNb/3dgqZHUta7ni4y+RG4Gorxv0pSAXFGeWAAAAAAAAAAAAAAAANCH6UMrMztDS1NbY2tze4OMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgIm/wD0pCAiwAGS9KDhiu1TWDD0oQsFAQr0pCD0oQYCCZ8AAAADCQcBASAIAPztRNDT/9M/0wDV+kDTf9MH0wfTB9MH0wfTB9MH0wfTB9MH0wfTB9MH+H/4fvh9+Hz4e/h6+Hn4ePh3+Hb4dfh0+HP4cvhv+G3VgCD4YPpA1NP/03/0BAEgbpXQ039vAt/4cNMH1woAgCH4YPhx+G74bPhr+Gp/+GH4Zvhj+GIB7z4QsjL//hDzws/+EbPCwDI+E34T/hS+FP4VPhV+Fb4V/hY+Fn4Wvhb+Fz4Xfhe+F9e8M7Lf8sHywfLB8sHywfLB8sHywfLB8sHywfLB8sHzsiAIPhAAc74SvhL+Ez4TvhQ+FGAIfhAXoDPEc8RzszL/8t/ASBus4AoARo4VyAFvIsgizwt/Ic8WMTHPFwHPg88RkzDPgeLLB8oAye1UAgEgDwwBYv9/jQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE+Gkh7UTQINdJwgENAfqOe9P/0z/TANX6QNN/0wfTB9MH0wfTB9MH0wfTB9MH0wfTB9MH0wf4f/h++H34fPh7+Hr4efh4+Hf4dvh1+HT4c/hy+G/4bdWAIPhg+kDU0//Tf/QEASBuldDTf28C3/hw0wfXCgCAIfhg+HH4bvhs+Gv4an/4Yfhm+GP4Yg4B5I6A4tMAAY4dgQIA1xgg+QEB0wABlNP/AwGTAvhC4iD4ZfkQ8qiV0wAB8nri0z8Bjh74QyG5IJ8wIPgjgQPoqIIIG3dAoLnekvhj4IA08jTY0x8B+CO88rnTHyHBAyKCEP////28sZFb4AHwAfhHbpEw3hsCASAlEAIBIB4RAgEgFhICAUgVEwH5tLZm+/wgt0l4Ae9o/CiQYIFJmEAyb3wm/SE3ieuF/+GAEEuYfCb8JOOC7xBHChh8JmGAEE4YfCZ8IpA3SRg4b11vb/l6fCb9ITeJ64X/4YBHDXwnfBO3iDg0U32wSrRTfzAY79Dav9sEuX2BSXwAcTb8OHwm/SE3ieuF/8AUADqOFfhJyM+FiM6Abc9Az4HPgcmBAID7AN7wAn/4ZwDRtPd0Ovwgt0l4Ae99IMrqaOh9IG/rhgBK6mjoaQBv6PwokGCBSZhAMm98Jv0hN4nrhf/hgBBLmHwm/CTjgu8QRwoYfCZhgBBOGHwmfCKQN0kYOG9db2/5enwAEPw/kEAQ/DAt+AE//DPAAQ+5Fqvn/wgt0BcB8o6A3vhG8nNx+GbR+EzDACCcMPhN+kJvE9cL/8AA3iCOFDD4TMAAIJww+E36Qm8T1wv/wwDe3/LgZPgA+E36Qm8T1wv/ji34TcjPhYjOjQPInEAAAAAAAAAAAAAAAAABzxbPgc+Bz5EhTuze+ErPFslx+wDe8AJ/+GcYARDtRNAg10nCARkB+o570//TP9MA1fpA03/TB9MH0wfTB9MH0wfTB9MH0wfTB9MH0wfTB/h/+H74ffh8+Hv4evh5+Hj4d/h2+HX4dPhz+HL4b/ht1YAg+GD6QNTT/9N/9AQBIG6V0NN/bwLf+HDTB9cKAIAh+GD4cfhu+Gz4a/hqf/hh+Gb4Y/hiGgEGjoDiGwH+9AVxIYBA9A6OJI0IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABN/4anIhgED0D5LIyd/4a3MhgED0DpPXC/+RcOL4bHQhgED0Do4kjQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE3/htcPhucBwB/PhvbfhwcPhxcPhycPhzcPh0cPh1cPh2cPh3cPh4cPh5cPh6cPh7cPh8cPh9cPh+jQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE+H+NCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAIPhgcB0AvIAh+GBwAYBA9A7yvdcL//hicPhjcPhmf/hhggr68ID4boBk+HGAZfhygGb4c4Bn+HSAaPh1gGn4doBq+HeAa/h4gGz4eYBt+HqAbvh7gG/4fIBw+H2Acfh+f4Ah+GABCbq/Fg4oHwH6+EFukvAD3vpBldTR0PpA39cNf5XU0dDTf9/XDX+V1NHQ03/f+kGV1NHQ+kDf1wwAldTR0NIA39TR+FEgwQKTMIBk3vhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/L0JMIA8uBk+FIgwQIgAXyTMIBk3iX4T7vy9PhdIMECkzCAZN4m+kJvE9cL/8MA8vT4XSDBApMwgGTeJvgoxwWz8vT4TfpCbxPXC//DACEC/I6Ajnf4WyDBApMwgGTe+CdvECW88vT4WyDBApMwgGTeJPhOvPL0+AAk+E8BobV/+G8iIPpCbxPXC/+T+Cgx3yQnf8jPhYDKAHPPQM4B+gKAac9Az4HPg8jPkGNIXAonzwt/+EzPC//4Tc8WIs8WJM8KACPPFM3JcfsAMOJfBiMiAArwAn/4ZwH6+E74J28QcGim+2CVaKb+YDHfobV/tgn4WyDBApMwgGTe+CdvECL4TqC1f7zy9CBy+wIl+E8BobV/+G8jIPpCbxPXC/+T+E0x3yd/yM+FgMoAc89AzoBtz0DPgc+DyM+QY0hcCijPC3/4TM8L//hNzxYizxYlzwoAJM8UzckkAAyBAID7AFsCASA9JgIBIDQnAgN96C0oAQess8qMKQH8+EFukvAD3vpBldTR0PpA39cNf5XU0dDTf9/6QZXU0dD6QN/XDACV1NHQ0gDf1NH4WCDBApMwgGTe+FBus/L0+FkgwQKTMIBk3vhJ+FAgbvJ/bxHHBfL0+FogwQKTMIBk3iT4UCBu8n9vELvy9PhSIMECkzCAZN4k+E+78vQjKgHiwgDy4GT4XSDBApMwgGTeJfgoxwWz8vT4TfpCbxPXC//DAI5N+E74J28QcGim+2CVaKb+YDHfobV/tgn4WyDBApMwgGTe+CdvECL4TqC1f7zy9CBy+wL4TvgnbxBwaKb7YJVopv5gMd+htX+2CXL7AjArAfyOMfhbIMECkzCAZN5waKb7YJVopv5gMd/4Trzy9PgnbxBwaKb7YJVopv5gMd+htX9y+wLiI/hPAaG1f/hv+FAgbvJ/bxAkobV/+FAgbvJ/bxFvAvhwJH/Iz4WAygBzz0DOgG3PQM+Bz4PIz5BjSFwKJc8Lf/hMzwv/+E3PFiQsAC7PFiPPCgAizxTNyYEAgPsAXwXwAn/4ZwHhrIaNX8ILdJeAHva4b/yupo6Gn/7/0gyupo6H0gb+uGv8rqaOhpv+/rhr/K6mjoab/v64a/yupo6Gm/7/0gyupo6H0gb+uGAErqaOhpAG/qaPwokGCBSZhAMm98Jv0hN4nrhf/hgBBLmHwm/CTjgu8QQuAdqOFDD4TMMAIJww+Ez4RSBukjBw3rre3/L0JcIA8uBk+FIgwQKTMIBk3ib4T7vy9PhcIMECkzCAZN4n+kJvE9cL/8MAIJQwKMAA3iCOEjAn+kJvE9cL/8AAIJQwKMMA3t/y9PhN+kJvE9cL/8MALwH+jkn4TvgnbxBwaKb7YJVopv5gMd+htX+2CfhbIMECkzCAZN74J28QIvhOoLV/KKC1f7zy9PhdIMECkzCAZN4o+E3HBbPy9CBy+wIwji/4WyDBApMwgGTe+CdvECYmoLV/vPL0+FsgwQKTMIBk3iT4Trzy9Cf4TL3y4GT4AOJtKDABlMjL/3BYgED0Q/hKcViAQPQW+EtyWIBA9BcoyMv/c1iAQPRDJ3RYgED0Fsj0AMn4S8jPhID0APQAz4HJIPkAyM+KAEDL/8nQJsIAMQGUjjshIPkA+Cj6Qm8SyM+GQMoHy//J0CghyM+FiM4B+gKAac9Az4PPgyLPFM+DyM+RotV8/snPFMlx+wAxMN4k+E36Qm8T1wv/wwAyAaKOTyj4TwGhtX/4byD6Qm8T1wv/k/hNMd8hf8jPhYDKAHPPQM6Abc9Az4HPg8jPkGNIXAoqzwt/+EzPC//4Tc8WIs8WJs8KACXPFM3JgQCA+wAzALqOUSj4TwGhtX/4byD6Qm8T1wv/k/goMd8mIn/Iz4WAygBzz0DOAfoCgGnPQM+Bz4PIz5BjSFwKKs8Lf/hMzwv/+E3PFiLPFibPCgAlzxTNyXH7AOJfA18I8AJ/+GcCAVg2NQD3tcK4c3wgt0l4Ae9o/Cg3Wct8KBA3eT/HE7hGhDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI3gXEQ4H/HFhHoaYD9IBgY5GfDkGdAMGegZ8DnwOfJXwrhzRC3kSwRZ4W/kOeLGJjkuP2AbxhJeAFvP/wzwAIBZjw3AQevEiX6OAH8+EFukvAD3vpBldTR0PpA3/pBldTR0PpA39cNf5XU0dDTf9/XDX+V1NHQ03/f+kGV1NHQ+kDf1wwAldTR0NIA39TR+FEgwQKTMIBk3vhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/L0+F0gOQFswQKTMIBk3ib6Qm8T1wv/wwDy9CTCAPLgZPhdIMECkzCAZN4nJ8cFs/L0IvhN+kJvE9cL/8MAOgHmjnH4TvgnbxBwaKb7YJVopv5gMd+htX+2CfhbIMECkzCAZN74J28QIvhOcqi1f6C1f7zy9CBy+wIh+kJvE9cL/5P4TTLfKMjPhYjOgG3PQM+Bz4PIz5D9WeVGKc8WKM8LfyPPFiXPCgAkzxTNyYEAgPsAMDsA3o5k+FsgwQKTMIBk3vgnbxAmvPL0+FsgwQKTMIBk3iX4TnKotX+88vT4ACD6Qm8T1wv/k/goMd8kKMjPhYjOAfoCgGnPQM+Bz4PIz5D9WeVGKM8WJ88LfyLPFiTPCgAjzxTNyXH7AOIwXwfwAn/4ZwDprvm4m+EFukvAD3tH4SvhL+Ez4TfhP+F+AIPhAgCH4QG8IIcD/jkUj0NMB+kAwMcjPhyDOgGDPQM+Bz4PIz5Kk+biaIm8oVQcozxYnzxQmzwv/Jc8WJM8Lf8gkzxYjzxYizwoAbILNzclx+wDeMJLwAt5/+GeAgEgST4CASBEPwEJtjSFwKBAAf74QW6S8APe1w1/ldTR0NN/39cN/5XU0dDT/9/6QZXU0dD6QN/6QZXU0dD6QN/XDACV1NHQ0gDf1NH4XiDBApMwgGTeIoAh+ECxIJww+F/6Qm8T1wv/wADf8vQkJG0iyMv/cFiAQPRD+EpxWIBA9Bb4S3JYgED0FyLIy/9zWIBAQQG+9EMhdFiAQPQWyPQAyfhLyM+EgPQA9ADPgckg+QDIz4oAQMv/ydADXwP4VCDBApMwgGTe+EkixwXy9PhdIMECkzCAZN4l+E3HBbMglTAm+Ey93/L0+E36Qm8T1wv/wwBCAcSOLvhO+CdvEHBopvtglWim/mAx36G1f7YJ+FsgwQKTMIBk3vgnbxAivPL0IHL7AjCOFvgnbxBwaKb7YJVopv5gMd+htX9y+wLiJvhPAaC1f/hvIiCcMPhf+kJvE9cL/8MA3kMAxo5D+F/Iz4WIzoBtz0DPgc+DyM+RZQR+5vgozxb4Ss8WKM8LfyfPC//IJ88W+EnPFibPFsj4T88LfyXPFM3NzcmBAID7AI4UI8jPhYjOgG3PQM+Bz4HJgQCA+wDiXwfwAn/4ZwEJthHyQSBFAfz4QW6S8APe1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/6QZXU0dD6QN/U0fhRIMECkzCAZN74TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y9CTCAPLgZPhSIMECkzCAZN4l+E+78vRGAaz4WyDBApMwgGTe+E36Qm8T1wv/wwAgnzBwaKb7YJVopv5gMd/CAN4gjh0w+E36Qm8T1wv/wAAgnjAk+CdvELsglDAkwgDe3t/y9CL4TfpCbxPXC//DAEcB2o5r+E74J28QcGim+2CVaKb+YDHfobV/tgly+wIl+E8BobV/+G8g+kJvE9cL/5P4TTHf+Ep/yM+FgMoAc89AzoBtz0DPgc+DyM+QuKIiqifPC3/4TM8L//hNzxYizxbIJc8WJM8Uzc3JgQCA+wBIAMCOVfgAJfhPAaG1f/hvIPpCbxPXC/+T+Cgx3yT4Sn/Iz4WAygBzz0DOAfoCgGnPQM+Bz4PIz5C4oiKqJ88Lf/hMzwv/+E3PFiLPFsglzxYkzxTNzclx+wDiMF8F8AJ/+GcCASBSSgIBIFFLAgEgTkwBCLMCWKpNAPr4QW6S8APe+kGV1NHQ+kDf0fhRIMECkzCAZN74TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y9PhPwADy4GT4ACDIz4UIzo0DyA+gAAAAAAAAAAAAAAAAAc8Wz4HPgcmBAKD7ADDwAn/4ZwEIsi/yDU8B/vhBbpLwA97XDX+V1NHQ03/f+kGV1NHQ+kDf+kGV1NHQ+kDf1NH4UyDBApMwgGTe+Er4SccF8vQjwgDy4GT4UiDBApMwgGTeJPhPu/L0+CdvEHBopvtglWim/mAx36G1f3L7AiP4TwGhtX/4b/hKf8jPhYDKAHPPQM6Abc9Az4FQAF7Pg8jPkLiiIqolzwt/+EzPC//4Tc8WJM8WyCTPFiPPFM3NyYEAgPsAXwTwAn/4ZwBztZ/nq/wgt0l4Ae9rhr/K6mjoab/v6PwpkGCBSZhAMm98JXwk44L5enwAEHwngNBav/w3mHgBP/wzwAIBIFZTAgEgVVQAXrJtt4jwA/hPyIvcAAAAAAAAAAAAAAAAIM8Wz4HPgc+SGbbeIiHPC3/JcfsAf/hnALazxQAP+EFukvAD3vpBldTR0PpA39H4USDBApMwgGTe+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8vT4ACCAIPhgMPACf/hnAgEgWlcBCLMh0XNYAf74QW6S8APe+kGV1NHQ+kDf1w1/ldTR0NN/39cNf5XU0dDTf9/R+FEgwQKTMIBk3vhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/L0+FcgwQKTMIBk3iLAACCWMPhQbrOz3/L0+E36Qm8T1wv/WQDUwwCOGvhO+CdvEHBopvtglWim/mAx36G1f7YJcvsCkvgA4vhQbrOOEvhQIG7yf28QIrqWICNvAvhw3pYgI28C+HDi+E36Qm8T1wv/jhX4ScjPhYjOgG3PQM+Bz4HJgQCA+wDeXwPwAn/4ZwEc2XAi0NMD+kAw+GmpOABbAUiOgOAhxwDcIdMfId0hwQMighD////9vLGRW+AB8AH4R26RMN5cAS4h1h8xcfAB8AP4ACDTHzIgghAY0hcCul0BtI6AjlIgghAuKIiquo5HIdN/M/hPAaC1f/hv+E36Qm8T1wv/ji/4TvgnbxBwaKb7YJVopv5gMd+htX+2CXL7AvhNyM+FiM6Abc9Az4HPgcmBAID7AN7e4lvwAl4B0CHTfzMg+E8BoLV/+G+AIPhA+kJvE9cL/8MAjkz4J28QcGim+2CVaKb+YDHfobV/cvsCgCD4QMjPhYjOgG3PQM+Bz4PIz5DqFdlC+CjPFvhKzxYizwt/yPhJzxb4T88Lf83NyYEAgPsAXwB+jjv4TfpCbxPXC/+OL/hO+CdvEHBopvtglWim/mAx36G1f7YJcvsC+E3Iz4WIzoBtz0DPgc+ByYEAgPsA3uIw";
    const TOKEN_WALLET_STATE_TIP3_V3: &str = "te6ccgECUwEAFmUAAm/ADJ6nSI+pviQzafXB5gmLzahu7MWbsAQ3NN0nZ4jxTD/CpqoRAwM9l8AAAC2O31yyEQDKEgVTQAMBAvMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwA7tPzMWNNSaXaK1RvRlLdSIlIehh8LvndIgPP8XtYTj0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAX/3ABgIDAMmAFSQopo5GzW/93YKmR1LWu54uMvkRuBqK8b9KUgFxRnlwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAIQ9KQgiu1T9KAGBAEK9KQg9KEFAAACASAKBwEC/wgC/n+NCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAT4aSHbPNMAAY4dgQIA1xgg+QEB0wABlNP/AwGTAvhC4iD4ZfkQ8qiV0wAB8nri0z8Bjh34QyG5IJ8wIPgjgQPoqIIIG3dAoLnekyD4Y+DyNNgw0x8B+CO88rkSCQIW0x8B2zz4R26OgN4NCwNu33Ai0NMD+kAw+GmpOAD4RH9vcYIImJaAb3Jtb3Nwb3T4ZI6A4CHHANwh0x8h3QHbPPhHbo6A3kkNCwEGW9s8DAIO+EFu4wDbPFJKBFggghAPAliqu46A4CCCECnEiX67joDgIIIQS/Fg4ruOgOAgghB1bM33u46A4D0pFQ4DPCCCEGi1Xz+64wIgghBx7uh1uuMCIIIQdWzN97rjAhEQDwPiMPhBbuMA0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZPhN+kJvE9cL/8MAjoCS+ADibfhv+E36Qm8T1wv/jhX4ScjPhYjOgG3PQM+Bz4HJgQCA+wDe2zx/+GdSSEoCsDD4QW7jAPpBldTR0PpA39cMAJXU0dDSAN/R+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8uBk+AAh+HAg+HJb2zx/+GdSSgLiMPhBbuMA+Ebyc3H4ZtH4TPhCuiCOFDD4TfpCbxPXC//AACCVMPhMwADf3vLgZPgAf/hy+E36Qm8T1wv/ji34TcjPhYjOjQPInEAAAAAAAAAAAAAAAAABzxbPgc+Bz5EhTuze+ErPFslx+wDe2zx/+GcSSgGS7UTQINdJwgGOPNP/0z/TANX6QPpA+HH4cPht+kDU0//Tf/QEASBuldDTf28C3/hv1woA+HL4bvhs+Gv4an/4Yfhm+GP4Yo6A4hMB/vQFcSGAQPQOjiSNCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATf+GpyIYBA9A+SyMnf+GtzIYBA9A6T1wv/kXDi+Gx0IYBA9A6OJI0IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABN/4bXD4bm0UAM74b40IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPhwjQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE+HFw+HJwAYBA9A7yvdcL//hicPhjcPhmf/hhA0AgghA/ENGru46A4CCCEElpWH+7joDgIIIQS/Fg4rrjAiEaFgL+MPhBbuMA+kGV1NHQ+kDf1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/XDACV1NHQ0gDf1NH4TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y4GQkwgDy4GQk+E678uBlJfpCbxPXC//DAFIXAjLy4G8l+CjHBbPy4G/4TfpCbxPXC//DAI6AGRgB5I5o+CdvECS88uBuI4IK+vCAvPLgbvgAJPhOAaG1f/huIyZ/yM+FgMoAc89AzgH6AoBpz0DPgc+DyM+QY0hcCibPC3/4TM8L//hNzxYk+kJvE9cL/8MAkSSS+CjizxYjzwoAIs8Uzclx+wDiXwbbPH/4Z0oB7oIK+vCA+CdvENs8obV/tgn4J28QIYIK+vCAoLV/vPLgbiBy+wIl+E4BobV/+G4mf8jPhYDKAHPPQM6Abc9Az4HPg8jPkGNIXAonzwt/+EzPC//4Tc8WJfpCbxPXC//DAJElkvhN4s8WJM8KACPPFM3JgQCB+wAwUQIoIIIQP1Z5UbrjAiCCEElpWH+64wIdGwKQMPhBbuMA0x/4RFhvdfhk0fhEcG9ycG9xgEBvdPhk+E4hwP+OIyPQ0wH6QDAxyM+HIM6AYM9Az4HPgc+TJaVh/iHPC3/JcPsAUhwBgI43+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPgfhEbxXPCx8hzwt/yfhEbxT7AOIw4wB/+GdKBPww+EFu4wD6QZXU0dD6QN/XDX+V1NHQ03/f+kGV1NHQ+kDf1wwAldTR0NIA39TR+E9us/Lga/hJ+E8gbvJ/bxHHBfLgbCP4TyBu8n9vELvy4G0j+E678uBlI8IA8uBkJPgoxwWz8uBv+E36Qm8T1wv/wwCOgI6A4iP4TgGhtX9SIB8eAbT4bvhPIG7yf28QJKG1f/hPIG7yf28RbwL4byR/yM+FgMoAc89AzoBtz0DPgc+DyM+QY0hcCiXPC3/4TM8L//hNzxYkzxYjzwoAIs8UzcmBAIH7AF8F2zx/+GdKAi7bPIIK+vCAvPLgbvgnbxDbPKG1f3L7AlFRAnKCCvrwgPgnbxDbPKG1f7YJ+CdvECGCCvrwgKC1f7zy4G4gcvsCggr68ID4J28Q2zyhtX+2CXL7AjBRUQIoIIIQLalNL7rjAiCCED8Q0au64wIoIgL+MPhBbuMA1w3/ldTR0NP/3/pBldTR0PpA39cNf5XU0dDTf9/XDX+V1NHQ03/f1w1/ldTR0NN/3/pBldTR0PpA39cMAJXU0dDSAN/U0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZCXCAFIjAvzy4GQl+E678uBlJvpCbxPXC//AACCUMCfAAN/y4G/4TfpCbxPXC//DAI6AjiD4J28QJSWgtX+88uBuI4IK+vCAvPLgbif4TL3y4GT4AOJtKMjL/3BYgED0Q/hKcViAQPQW+EtyWIBA9BcoyMv/c1iAQPRDJ3RYgED0Fsj0AMknJAH8+EvIz4SA9AD0AM+ByY0IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCbCAI43ISD5APgo+kJvEsjPhkDKB8v/ydAoIcjPhYjOAfoCgGnPQM+Dz4MizxTPgc+RotV8/slx+wAxMZ0h+QDIz4oAQMv/ydAx4vhNJQG4+kJvE9cL/8MAjlEn+E4BobV/+G4gf8jPhYDKAHPPQM6Abc9Az4HPg8jPkGNIXAopzwt/+EzPC//4Tc8WJvpCbxPXC//DAJEmkvhN4s8WJc8KACTPFM3JgQCB+wAmAbyOUyf4TgGhtX/4biUhf8jPhYDKAHPPQM4B+gKAac9Az4HPg8jPkGNIXAopzwt/+EzPC//4Tc8WJvpCbxPXC//DAJEmkvgo4s8WJc8KACTPFM3JcfsA4ltfCNs8f/hnSgFmggr68ID4J28Q2zyhtX+2CfgnbxAhggr68ICgtX8noLV/vPLgbif4TccFs/LgbyBy+wIwUQHoMNMf+ERYb3X4ZNFzIcD/jiMj0NMB+kAwMcjPhyDOgGDPQM+Bz4HPkralNL4hzwsfyXD7AI43+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPgfhEbxXPCx8hzwsfyfhEbxT7AOIw4wB/+GdKA0AgghAYbXO8u46A4CCCECcWEJG7joDgIIIQKcSJfrrjAjUtKgL+MPhBbuMA+kGV1NHQ+kDf+kGV1NHQ+kDf1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/XDACV1NHQ0gDf1NH4TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y4GQl+kJvE9cL/8MA8uBvJFIrAvbCAPLgZCYmxwWz8uBv+E36Qm8T1wv/wwCOgI5X+CdvECS88uBuI4IK+vCAcqi1f7zy4G74ACMnyM+FiM4B+gKAac9Az4HPg8jPkP1Z5UYnzxYmzwt/JPpCbxPXC//DAJEkkvgo4s8WI88KACLPFM3JcfsA4l8H2zx/+GcsSgHMggr68ID4J28Q2zyhtX+2CfgnbxAhggr68IByqLV/oLV/vPLgbiBy+wInyM+FiM6Abc9Az4HPg8jPkP1Z5UYozxYnzwt/JfpCbxPXC//DAJElkvhN4s8WJM8KACPPFM3JgQCB+wAwUQIoIIIQGNIXArrjAiCCECcWEJG64wIwLgL0MPhBbuMA0x/4RFhvdfhk0fhEcG9ycG9xgEBvdPhk+Er4S/hM+E34TvhQ+FH4Um8IIcD/jkUj0NMB+kAwMcjPhyDOgGDPQM+Bz4PIz5KcWEJGIm8oVQcozxYnzxQmzwv/Jc8WJM8Lf8gkzxYjzxYizwoAbILNzclw+wBSLwHEjln4RCBvEyFvEvhJVQJvEchyz0DKAHPPQM4B+gL0AIBoz0DPgc+DyPhEbxXPCx8ibyhVByjPFifPFCbPC/8lzxYkzwt/yCTPFiPPFiLPCgBsgs3NyfhEbxT7AOIw4wB/+GdKAv4w+EFu4wDXDX+V1NHQ03/f1w3/ldTR0NP/3/pBldTR0PpA3/pBldTR0PpA39cMAJXU0dDSAN/U0SH4UrEgnDD4UPpCbxPXC//AAN/y4HAkJG0iyMv/cFiAQPRD+EpxWIBA9Bb4S3JYgED0FyLIy/9zWIBA9EMhdFiAQPQWyPQAUjEDvsn4S8jPhID0APQAz4HJIPkAyM+KAEDL/8nQMWwh+EkhxwXy4Gck+E3HBbMglTAl+Ey93/Lgb/hN+kJvE9cL/8MAjoCOgOIm+E4BoLV/+G4iIJww+FD6Qm8T1wv/wwDeNDMyAciOQ/hQyM+FiM6Abc9Az4HPg8jPkWUEfub4KM8W+ErPFijPC38nzwv/yCfPFvhJzxYmzxbI+E7PC38lzxTNzc3JgQCA+wCOFCPIz4WIzoBtz0DPgc+ByYEAgPsA4jBfBts8f/hnSgEY+CdvENs8obV/cvsCUQE8ggr68ID4J28Q2zyhtX+2CfgnbxAhvPLgbiBy+wIwUQIoIIIQEEfJBLrjAiCCEBhtc7y64wI4NgKsMPhBbuMA0x/4RFhvdfhk0fhEcG9ycG9xgEBvdPhk+E9us5b4TyBu8n+OJ3CNCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARvAuIhwP9SNwHujiwj0NMB+kAwMcjPhyDOgGDPQM+Bz4HPkmG1zvIhbyJYIs8LfyHPFmwhyXD7AI5A+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPgfhEbxXPCx8hbyJYIs8LfyHPFmwhyfhEbxT7AOIw4wB/+GdKA/Yw+EFu4wDXDX+V1NHQ03/f1w1/ldTR0NN/3/pBldTR0PpA3/pBldTR0PpA39TR+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8uBkJMIA8uBkJPhOu/LgZfhN+kJvE9cL/8MAII6A3iBSPDkCYI4dMPhN+kJvE9cL/8AAIJ4wI/gnbxC7IJQwI8IA3t7f8uBu+E36Qm8T1wv/wwCOgDs6AcKOV/gAJPhOAaG1f/huI/hKf8jPhYDKAHPPQM4B+gKAac9Az4HPg8jPkLiiIqomzwt/+EzPC//4Tc8WJPpCbxPXC//DAJEkkvgo4s8WyCTPFiPPFM3NyXD7AOJfBds8f/hnSgHMggr68ID4J28Q2zyhtX+2CXL7AiT4TgGhtX/4bvhKf8jPhYDKAHPPQM6Abc9Az4HPg8jPkLiiIqomzwt/+EzPC//4Tc8WJPpCbxPXC//DAJEkkvhN4s8WyCTPFiPPFM3NyYEAgPsAUQEKMNs8wgBRA0AgghAFxQAPu46A4CCCEAwv8g27joDgIIIQDwJYqrrjAkRAPgMuMPhBbuMA+kGV1NHQ+kDf0ds82zx/+GdSP0oAvPhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZPhOwADy4GT4ACDIz4UIzo0DyA+gAAAAAAAAAAAAAAAAAc8Wz4HPgcmBAKD7ADACKCCCEAs/z1e64wIgghAML/INuuMCQ0ED/jD4QW7jANcNf5XU0dDTf9/6QZXU0dD6QN/6QZXU0dD6QN/U0fhK+EnHBfLgZiPCAPLgZCP4Trvy4GX4J28Q2zyhtX9y+wIj+E4BobV/+G74Sn/Iz4WAygBzz0DOgG3PQM+Bz4PIz5C4oiKqJc8Lf/hMzwv/+E3PFiTPFsgkzxZSUUIBJCPPFM3NyYEAgPsAXwTbPH/4Z0oCVjD4QW7jANcNf5XU0dDTf9/R+Er4SccF8uBm+AAg+E4BoLV/+G4w2zx/+GdSSgImIIILIdFzuuMCIIIQBcUAD7rjAkZFApYw+EFu4wD6QZXU0dD6QN/R+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8uBk+AAg+HEw2zx/+GdSSgPwMPhBbuMA+kGV1NHQ+kDf1w1/ldTR0NN/39cNf5XU0dDTf9/R+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8uBkIcAAIJYw+E9us7Pf8uBq+E36Qm8T1wv/wwCOgJL4AOL4T26zUkhHAYiOEvhPIG7yf28QIrqWICNvAvhv3pYgI28C+G/i+E36Qm8T1wv/jhX4ScjPhYjOgG3PQM+Bz4HJgQCA+wDeXwPbPH/4Z0oBJoIK+vCA+CdvENs8obV/tgly+wJRBEAh1h8x+EFu4wD4ACDTHzIgghAY0hcCuo6AjoDiMDDbPFJNS0oArPhCyMv/+EPPCz/4Rs8LAMj4TfhQ+FFeIM7OzvhK+Ev4TPhO+E/4Ul5gzxHOzMv/y38BIG6zjhXIAW8iyCLPC38hzxZsIc8XAc+DzxGTMM+B4soAye1UARYgghAuKIiquo6A3kwBMCHTfzP4TgGgtX/4bvhN+kJvE9cL/46A3k8CPCHTfzMg+E4BoLV/+G74UfpCbxPXC//DAI6AjoDiMFBOARj4TfpCbxPXC/+OgN5PAVCCCvrwgPgnbxDbPKG1f7YJcvsC+E3Iz4WIzoBtz0DPgc+ByYEAgPsAUQGA+CdvENs8obV/cvsC+FHIz4WIzoBtz0DPgc+DyM+Q6hXZQvgozxb4Ss8WIs8Lf8j4Sc8W+E7PC3/NzcmBAID7AFEAGHBopvtglWim/mAx3wB+7UTQ0//TP9MA1fpA+kD4cfhw+G36QNTT/9N/9AQBIG6V0NN/bwLf+G/XCgD4cvhu+Gz4a/hqf/hh+Gb4Y/hi";

    fn root_meta_contract() -> ExistingContract {
        prepare_contract(ROOT_META_STATE)
    }

    const ROOT_META_STATE: &str = "te6ccgECIAEABTMAAm/ABAsZKyqaNn/39hhm8Rc7ZuF68HUBMp404dxi62++27CCQIk0AwM8/EgAAC2M9HVPCSTj38rTQAQBAdYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwArQkYQ/69uvcjCL+cRQZ4F+JUllwoppK1xBh/jH+rbIGAHdp+ZixpqTS7RWqN6MpbqREpD0MPhd87pEB5/i9rCcewIBAtADAEOAFfqJgTLmfQyxoEQM8CDYAG6TC3wCaoXgObqDWRryUaNQAhD0pCCK7VP0oAcFAQr0pCD0oQYAAAIBIAkIAuL/f40IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPhpIds80wABjhKBAgDXGCD5AVj4QiD4ZfkQ8qje0z8Bjh34QyG5IJ8wIPgjgQPoqIIIG3dAoLnekyD4Y+DyNNgw0x8B2zz4R27yfBQKAUDfcCLQ0wP6QDD4aak4ANwhxwDcIdMfId0B2zz4R27yfAoEWCCCEDCEvEi7joDgIIIQR1ZU3LuOgOAgghBfC8/eu46A4CCCEH04jJC7joDgFxIOCwIoIIIQZxU4/rrjAiCCEH04jJC64wINDAFW2zz4TMiL3AAAAAAAAAAAAAAAACDPFs+Bz4HPk/TiMkIhAfQAyXD7AH/4Zx8DqjD4QW7jANH4SY0Ek93bmFibGU6IG5vdCBvd25lcoMjOyfhKIscF8uh7jQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE2zww2zx/+GcfHh0CKCCCEFoF2sq64wIgghBfC8/euuMCEA8BVNs8+ErIi9wAAAAAAAAAAAAAAAAgzxbPgc+Bz5N8Lz96Ic8WyXD7AH/4Zx8DcjD4QW7jANMP0ds8IcD/jiIj0NMB+kAwMcjPhyDOgGDPQM+Bz4HPk2gXayohzxTJcPsA3jDjAH/4Zx8RHQAeyMkh+EyAEPQPksjJ3zExAiggghA3KV4guuMCIIIQR1ZU3LrjAhYTA5Iw+EFu4wD4RvJzcfhm+kDRjQaUm9vdE1ldGE6IFdyb25nIGRlcGxveSBrZXmDIzsn4QvhFIG6SMHDeuvLoZfgAINs8MNs8f/hnFB4dAUrtRNAg10nCAY4b0//TP9MA+kD6QPQF+Gz4a/hqf/hh+Gb4Y/hiFQDmjnD0BY0IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPhqcSGAQPQOjiSNCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATf+Gtt+GxwAYBA9A7yvdcL//hicPhjcPhmf/hh4gFU2zz4S8iL3AAAAAAAAAAAAAAAACDPFs+Bz4HPktyleIIhzxbJcPsAf/hnHwIoIIIQDgTSnrrjAiCCEDCEvEi64wIcGAMiMPhBbuMA0w/U0ds82zx/+GcfGR0CkvhJjQST3duYWJsZTogbm90IG93bmVygyM7J+EoixwXy6Hv4J28Q2zyhtX9y+wIiIts8+EnIz4WIzoBtz0DPgc+ByYEAgfsAMFsbGgAa+EwiASJZgBD0F/hsWwAYcGim+2CVaKb+YDHfA2ow+EFu4wD6QNH4SY0Ek93bmFibGU6IG5vdCBvd25lcoMjOyfhKIscF8uh7Ids8MDDbPH/4Zx8eHQA8+ELIy//4Q88LP/hGzwsA+Er4S/hMXiDOzvQAye1UAAgg+GowADztRNDT/9M/0wD6QPpA9AX4bPhr+Gp/+GH4Zvhj+GI=";

    #[test]
    fn root_meta_address() {
        let root_contract_address =
            convert_address("0:eed3f331634d49a5da2b546f4652dd4889487a187c2ef9dd2203cff17b584e3d");

        let root_meta_address = compute_root_meta_address(&root_contract_address);
        assert_eq!(
            root_meta_address,
            convert_address("0:40b192b2a9a367ff7f61866f1173b66e17af07501329e34e1dc62eb6fbedbb08")
        )
    }

    #[test]
    fn root_meta_details() {
        let contract = root_meta_contract();
        let proxy_address = RootMetaContractState(&contract).get_details().unwrap();
        assert_eq!(
            proxy_address.proxy_address,
            convert_address("0:afd44c099733e8658d0220678106c00374985be013542f01cdd41ac8d7928d1a")
        );
    }

    #[test]
    fn get_token_wallet_balance() {
        let versions = [
            TokenWalletVersion::Tip3v1,
            TokenWalletVersion::Tip3v2,
            TokenWalletVersion::Tip3v3,
        ];

        for &version in &versions {
            let contract = token_wallet_contract(version);
            let state = TokenWalletContractState(&contract);

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
                TokenWalletVersion::Tip3v1,
                "0:07b83517856b354b2d756c6663e01a5f00e08c102d7383ffe134d833c3f7969a",
            ),
            (
                TokenWalletVersion::Tip3v2,
                "0:f031a8ed14ed04e761ec0260d5ab8907e4de0064369e5100fe71459457602425",
            ),
            (
                TokenWalletVersion::Tip3v3,
                "0:c9ea7488fa9be243369f5c1e6098bcda86eecc59bb0043734dd276788f14c3fc",
            ),
        ];

        // guess details from state for each version
        for &(version, token_wallet) in &versions {
            let contract = root_token_contract(version);
            let state = RootTokenContractState(&contract);

            let details = state.guess_details().unwrap();
            assert_eq!(details.version, version);

            let address = state
                .get_wallet_address(details.version, &convert_address(owner_address))
                .unwrap();

            assert_eq!(address, convert_address(token_wallet));
        }
    }
}
