use std::convert::TryFrom;
use std::sync::Arc;

use crate::core::models::*;
use crate::core::parsing::*;
use crate::transport::models::{RawContractState, RawTransaction};
use crate::transport::Transport;
use anyhow::Result;
use nekoton_abi::num_traits::ToPrimitive;
use nekoton_abi::*;
use nekoton_contracts::jetton::{JettonRootData, JettonRootMeta, JettonWalletData};
use nekoton_utils::*;
use num_bigint::{BigInt, BigUint, ToBigInt};
use ton_block::{MsgAddressInt, Serializable};
use ton_types::{BuilderData, IBitstring, SliceData};

use super::{utils, ContractSubscription, InternalMessage};

pub const JETTON_TRANSFER_OPCODE: u32 = 0x0f8a7ea5;
pub const JETTON_INTERNAL_TRANSFER_OPCODE: u32 = 0x178d4519;

pub struct JettonWallet {
    clock: Arc<dyn Clock>,
    contract_subscription: ContractSubscription,
    handler: Arc<dyn JettonWalletSubscriptionHandler>,
    root: MsgAddressInt,
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
        preload_transactions: bool,
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

        let contract_subscription = {
            let handler = handler.as_ref();
            // NOTE: create handler beforehead to prevent lifetime issues
            let mut on_transactions_found = match preload_transactions {
                true => Some(make_transactions_handler(handler)),
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
                &mut make_contract_state_handler(clock.clone(), &mut balance),
                on_transactions_found,
            )
            .await?
        };

        handler.on_balance_changed(balance.clone());

        Ok(Self {
            clock,
            contract_subscription,
            handler,
            owner,
            balance,
            root: root_token_contract,
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

    pub async fn estimate_min_attached_amount(&self, destination: MsgAddressInt) -> Result<u64> {
        let transport = self.contract_subscription.transport();

        let state = match transport.get_contract_state(&self.root).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists { .. } => {
                return Err(JettonWalletError::InvalidRootTokenContract.into())
            }
        };
        let state =
            nekoton_contracts::jetton::RootTokenContract(state.as_context(self.clock.as_ref()));

        let token_wallet = state.get_wallet_address(&destination)?;

        let attached_amount = match transport.get_contract_state(&token_wallet).await? {
            RawContractState::Exists(_) => 50_000_000, // 0.05 TON
            RawContractState::NotExists { .. } => 100_000_000, // 0.1 TON
        };

        Ok(attached_amount)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_transfer(
        &self,
        amount: BigUint,
        destination: MsgAddressInt,
        remaining_gas_to: MsgAddressInt,
        custom_payload: Option<ton_types::Cell>,
        callback_value: BigUint,
        callback_payload: Option<ton_types::Cell>,
        attached_amount: u128,
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

pub async fn get_wallet_data(
    clock: &dyn Clock,
    transport: Arc<dyn Transport>,
    address: &MsgAddressInt,
) -> Result<JettonWalletData> {
    let mut state = match transport.get_contract_state(address).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(JettonWalletError::InvalidTokenWalletContract.into())
        }
    };

    utils::update_library_cell(transport.as_ref(), &mut state.account.storage.state).await?;

    let token_wallet_details =
        nekoton_contracts::jetton::TokenWalletContract(state.as_context(clock)).get_details()?;

    Ok(token_wallet_details)
}

pub async fn get_token_root_meta(
    clock: &dyn Clock,
    transport: Arc<dyn Transport>,
    address: &MsgAddressInt,
) -> Result<JettonRootMeta> {
    let mut state = match transport.get_contract_state(address).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(JettonWalletError::InvalidTokenWalletContract.into())
        }
    };

    utils::update_library_cell(transport.as_ref(), &mut state.account.storage.state).await?;

    let token_root_meta =
        nekoton_contracts::jetton::RootTokenContract(state.as_context(clock)).get_meta()?;

    Ok(token_root_meta)
}

pub async fn get_token_wallet_details(
    clock: &dyn Clock,
    transport: Arc<dyn Transport>,
    token_wallet: &MsgAddressInt,
) -> Result<(JettonWalletData, JettonRootData)> {
    let mut token_wallet_state = match transport.get_contract_state(token_wallet).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(JettonWalletError::InvalidTokenWalletContract.into())
        }
    };

    utils::update_library_cell(
        transport.as_ref(),
        &mut token_wallet_state.account.storage.state,
    )
    .await?;

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
    let mut state = match transport.get_contract_state(root_token_contract).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(JettonWalletError::InvalidRootTokenContract.into())
        }
    };

    utils::update_library_cell(transport, &mut state.account.storage.state).await?;

    nekoton_contracts::jetton::RootTokenContract(state.as_context(clock)).get_details()
}

pub async fn get_token_root_details_from_token_wallet(
    clock: &dyn Clock,
    transport: Arc<dyn Transport>,
    token_wallet_address: &MsgAddressInt,
) -> Result<(MsgAddressInt, JettonRootData)> {
    let mut state = match transport.get_contract_state(token_wallet_address).await? {
        RawContractState::Exists(state) => state,
        RawContractState::NotExists { .. } => {
            return Err(JettonWalletError::WalletNotDeployed.into())
        }
    };

    utils::update_library_cell(transport.as_ref(), &mut state.account.storage.state).await?;

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
) -> impl FnMut(&RawContractState) + '_ {
    move |contract_state| {
        if let RawContractState::Exists(state) = contract_state {
            if let Ok(new_balance) =
                nekoton_contracts::jetton::TokenWalletContract(state.as_context(clock.as_ref()))
                    .balance()
            {
                *balance = new_balance
            }
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
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use nekoton_abi::num_bigint::BigUint;
    use nekoton_abi::num_traits::FromPrimitive;
    use nekoton_abi::ExecutionContext;
    use nekoton_contracts::jetton;
    use nekoton_utils::SimpleClock;
    use ton_block::MsgAddressInt;

    #[test]
    fn usdt_root_token_contract() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("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").unwrap().as_slice()).unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::RootTokenContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let total_supply = contract.total_supply()?;
        assert_eq!(total_supply, BigUint::from_u128(1229976002510000).unwrap());

        Ok(())
    }

    #[test]
    fn tonup_root_token_contract() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("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").unwrap().as_slice()).unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::RootTokenContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let name = contract.name()?;
        assert_eq!(name.unwrap(), "TonUP");

        let symbol = contract.symbol()?;
        assert_eq!(symbol.unwrap(), "UP");

        let decimals = contract.decimals()?;
        assert_eq!(decimals.unwrap(), 9);

        let total_supply = contract.total_supply()?;
        assert_eq!(total_supply, BigUint::from_u128(56837335582855498).unwrap());

        let wallet_code = contract.wallet_code()?;
        let expected_code = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6cckECEQEAAyMAART/APSkE/S88sgLAQIBYgIDAgLMBAUAG6D2BdqJofQB9IH0gahhAgHUBgcCASAICQDDCDHAJJfBOAB0NMDAXGwlRNfA/AM4PpA+kAx+gAxcdch+gAx+gAwc6m0AALTH4IQD4p+pVIgupUxNFnwCeCCEBeNRRlSILqWMUREA/AK4DWCEFlfB7y6k1nwC+BfBIQP8vCAAET6RDBwuvLhTYAIBIAoLAIPUAQa5D2omh9AH0gfSBqGAJpj8EIC8aijKkQXUEIPe7L7wndCVj5cWLpn5j9ABgJ0CgR5CgCfQEsZ4sA54tmZPaqQB8VA9M/+gD6QCHwAe1E0PoA+kD6QNQwUTahUirHBfLiwSjC//LiwlQ0QnBUIBNUFAPIUAT6AljPFgHPFszJIsjLARL0APQAywDJIPkAcHTIywLKB8v/ydAE+kD0BDH6ACDXScIA8uLEd4AYyMsFUAjPFnD6AhfLaxPMgMAgEgDQ4AnoIQF41FGcjLHxnLP1AH+gIizxZQBs8WJfoCUAPPFslQBcwjkXKRceJQCKgToIIJycOAoBS88uLFBMmAQPsAECPIUAT6AljPFgHPFszJ7VQC9ztRND6APpA+kDUMAjTP/oAUVGgBfpA+kBTW8cFVHNtcFQgE1QUA8hQBPoCWM8WAc8WzMkiyMsBEvQA9ADLAMn5AHB0yMsCygfL/8nQUA3HBRyx8uLDCvoAUaihggiYloBmtgihggiYloCgGKEnlxBJEDg3XwTjDSXXCwGAPEADXO1E0PoA+kD6QNQwB9M/+gD6QDBRUaFSSccF8uLBJ8L/8uLCBYIJMS0AoBa88uLDghB73ZfeyMsfFcs/UAP6AiLPFgHPFslxgBjIywUkzxZw+gLLaszJgED7AEATyFAE+gJYzxYBzxbMye1UgAHBSeaAYoYIQc2LQnMjLH1Iwyz9Y+gJQB88WUAfPFslxgBDIywUkzxZQBvoCFctqFMzJcfsAECQQIwB8wwAjwgCwjiGCENUydttwgBDIywVQCM8WUAT6AhbLahLLHxLLP8ly+wCTNWwh4gPIUAT6AljPFgHPFszJ7VSV6u3X")?.as_slice())?;
        assert_eq!(wallet_code, expected_code);

        let token_address = contract.get_wallet_address(&MsgAddressInt::default())?;
        assert_eq!(
            token_address.to_string(),
            "0:0c6a835483369275c9ae76e7e31d9eda0845368045a8ec2ed78609d96bb0a087"
        );

        Ok(())
    }

    #[test]
    fn tonup_wallet_token_contract() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("te6ccgECEwEAA6kAAm6ADhM4pof2jbUfk8bYdFfLChAB6cUG0z98g+xOrlf4LCzkTQz7BmMVjoAAAVA6z3tMKgC1Y0MmAgEBj0dzWUAIAc+mHGAhdljL3SZo8QcvtpqlV+kMrO8+wlbsMF9hxLGVACvaf0JMrv6BOvPpAgee08uQM/uRpUd//fhA7Nm8twzvYAIBFP8A9KQT9LzyyAsDAgFiBQQAG6D2BdqJofQB9IH0gahhAgLMEAYCASAIBwCD1AEGuQ9qJofQB9IH0gahgCaY/BCAvGooypEF1BCD3uy+8J3QlY+XFi6Z+Y/QAYCdAoEeQoAn0BLGeLAOeLZmT2qkAgEgDgkCASALCgDXO1E0PoA+kD6QNQwB9M/+gD6QDBRUaFSSccF8uLBJ8L/8uLCBYIJMS0AoBa88uLDghB73ZfeyMsfFcs/UAP6AiLPFgHPFslxgBjIywUkzxZw+gLLaszJgED7AEATyFAE+gJYzxYBzxbMye1UgAvc7UTQ+gD6QPpA1DAI0z/6AFFRoAX6QPpAU1vHBVRzbXBUIBNUFAPIUAT6AljPFgHPFszJIsjLARL0APQAywDJ+QBwdMjLAsoHy//J0FANxwUcsfLiwwr6AFGooYIImJaAZrYIoYIImJaAoBihJ5cQSRA4N18E4w0l1wsBgDQwAfMMAI8IAsI4hghDVMnbbcIAQyMsFUAjPFlAE+gIWy2oSyx8Syz/JcvsAkzVsIeIDyFAE+gJYzxYBzxbMye1UAHBSeaAYoYIQc2LQnMjLH1Iwyz9Y+gJQB88WUAfPFslxgBDIywUkzxZQBvoCFctqFMzJcfsAECQQIwHxUD0z/6APpAIfAB7UTQ+gD6QPpA1DBRNqFSKscF8uLBKML/8uLCVDRCcFQgE1QUA8hQBPoCWM8WAc8WzMkiyMsBEvQA9ADLAMkg+QBwdMjLAsoHy//J0AT6QPQEMfoAINdJwgDy4sR3gBjIywVQCM8WcPoCF8trE8yA8AnoIQF41FGcjLHxnLP1AH+gIizxZQBs8WJfoCUAPPFslQBcwjkXKRceJQCKgToIIJycOAoBS88uLFBMmAQPsAECPIUAT6AljPFgHPFszJ7VQCAdQSEQARPpEMHC68uFNgAMMIMcAkl8E4AHQ0wMBcbCVE18D8Azg+kD6QDH6ADFx1yH6ADH6ADBzqbQAAtMfghAPin6lUiC6lTE0WfAJ4IIQF41FGVIgupYxREQD8ArgNYIQWV8HvLqTWfAL4F8EhA/y8IA==").unwrap().as_slice()).unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::TokenWalletContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let balance = contract.balance()?;
        assert_eq!(balance, BigUint::from_u128(2000000000).unwrap());

        let root = contract.root()?;
        assert_eq!(
            root,
            MsgAddressInt::from_str(
                "0:af69fd0932bbfa04ebcfa4081e7b4f2e40cfee46951dfff7e103b366f2dc33bd"
            )?
        );

        Ok(())
    }

    #[test]
    fn wallet_address() -> anyhow::Result<()> {
        let cell = ton_types::deserialize_tree_of_cells(&mut base64::decode("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").unwrap().as_slice()).unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::RootTokenContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let owner = nekoton_utils::unpack_std_smc_addr(
            "EQC-D0YPvNUq92FeG7_ZGFQY-L-lZ0wayn8arc4AKElbSo6v",
            true,
        )?;

        let expected = nekoton_utils::unpack_std_smc_addr(
            "EQBWqBJJQriSjGTOBXPPSZjZoTnESO3RqPLrO6enXSq--yes",
            true,
        )?;

        let address = contract.get_wallet_address(&owner)?;
        assert_eq!(address, expected);

        Ok(())
    }

    #[test]
    fn mintless_points_root_token_contract() -> anyhow::Result<()> {
        let cell =
            ton_types::deserialize_tree_of_cells(&mut base64::decode("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").unwrap().as_slice())
                .unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::RootTokenContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });



        let details = contract.get_details()?;
        assert_eq!(details.admin_address, MsgAddressInt::default());

        println!("details {:?}", details.total_supply);

        let owner = nekoton_utils::unpack_std_smc_addr(
            "UQA8aeJrWO-5DZ-1Zs2juDYfT4V_ud2KY8gegMd33gHjeUaF",
            true,
        )?;

        let address = contract.get_wallet_address(&owner)?;
        assert_eq!(
            address,
            MsgAddressInt::from_str(
                "0:3d97d11909a20de878c4400ed241a714065d3a0f4d4f0d60ecaf0dbe11cdd1bc"
            )?
        );

        Ok(())
    }

    #[test]
    fn dai_root_token_contract() -> anyhow::Result<()> {
        let cell =
            ton_types::deserialize_tree_of_cells(&mut base64::decode("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").unwrap().as_slice())
                .unwrap();
        let state = nekoton_utils::deserialize_account_stuff(cell)?;

        let contract = jetton::RootTokenContract(ExecutionContext {
            clock: &SimpleClock,
            account_stuff: &state,
        });

        let meta = contract.get_meta()?;
        assert_eq!(meta.name, "Dai Token");
        assert_eq!(meta.symbol, "DAI");
        assert_eq!(meta.decimals, 18);
        assert_eq!(meta.base_chain_id, "56");

        Ok(())
    }
}
