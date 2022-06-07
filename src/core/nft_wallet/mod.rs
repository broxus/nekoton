use crate::core::models::{
    NftTransaction, NftVersion, Transaction, TransactionWithData, TransactionsBatchInfo,
};
use crate::core::parsing::parse_nft_transaction;
use crate::core::{ContractSubscription, InternalMessage};
use crate::transport::models::{ExistingContract, RawContractState, RawTransaction};
use crate::transport::Transport;
use anyhow::Result;
use nekoton_abi::map_address_tuple::*;
use nekoton_abi::{MessageBuilder, NftCallbackPayload};
use nekoton_contracts::nft_index::index_contract::IndexGetInfoOutputs;
use nekoton_contracts::tip4_1::nft_contract;
use nekoton_contracts::tip4_1::nft_contract::*;
use nekoton_contracts::*;
use nekoton_utils::Clock;
use std::collections::BTreeMap;
use std::sync::Arc;
use ton_block::{MsgAddressInt, Serializable};
use ton_types::{BuilderData, Cell, UInt256};

const NFT_STAMP: &[u8; 3] = b"nft";

pub struct NftCollection {
    collection_address: MsgAddressInt,
    nfts: Vec<MsgAddressInt>,
}

impl NftCollection {
    pub fn collection_address(&self) -> &MsgAddressInt {
        &self.collection_address
    }
    pub fn collection_nft_list(&self) -> &Vec<MsgAddressInt> {
        &self.nfts
    }
    pub async fn get(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        owner: MsgAddressInt,
        collection_address: MsgAddressInt,
    ) -> Result<NftCollection> {
        let state = match transport.get_contract_state(&collection_address).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists => return Err(NftError::ContractNotExist.into()),
        };
        let collection_state = CollectionContractState(&state);

        let nfts = match collection_state.check_collection_supported_interface(clock.as_ref())? {
            Some(NftVersion::Tip4_3) => {
                let index_code = collection_state.resolve_collection_index_code(clock.as_ref())?;
                let code_hash = collection_state.get_collection_code_hash(&owner, index_code)?;
                transport
                    .get_accounts_by_code_hash(&code_hash, 100, &None)
                    .await?
            }
            None => return Err(NftError::InvalidCollectionContract.into()),
            _ => return Err(NftError::UnsupportedInterfaceVersion.into()),
        };

        Ok(Self {
            collection_address,
            nfts,
        })
    }
}

pub struct Nft {
    address: MsgAddressInt,
    collection_address: MsgAddressInt,
    owner: MsgAddressInt,
    manager: MsgAddressInt,
    json_info: Option<String>,
    contract_subscription: ContractSubscription,
    //handler: Arc<dyn NftSubscriptionHandler>,
}

impl Nft {
    pub async fn get_by_index_address(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        index_address: &MsgAddressInt,
        handler: Arc<dyn NftSubscriptionHandler>,
    ) -> Result<Nft> {
        let state = match transport.get_contract_state(index_address).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists => return Err(NftError::ContractNotExist.into()),
        };
        let index_state = IndexContractState(&state);

        let info = index_state.get_info(clock.as_ref()).await?;
        Nft::get_nft_info(&info.nft, transport, clock, handler).await
    }
    pub async fn get(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        address: &MsgAddressInt,
        handler: Arc<dyn NftSubscriptionHandler>,
    ) -> Result<Nft> {
        Nft::get_nft_info(address, transport, clock, handler).await
    }

    async fn get_nft_info(
        nft_address: &MsgAddressInt,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
        handler: Arc<dyn NftSubscriptionHandler>,
    ) -> Result<Nft> {
        let state = match transport.get_contract_state(nft_address).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists => return Err(NftError::ContractNotExist.into()),
        };
        let nft_state = NftContractState(&state);

        let ctx = nft_state.0.as_context(clock.as_ref());
        let tip6_interface = tip6::SidContract(ctx);

        let mut info = if tip6_interface.supports_interface(tip4_1::nft_contract::INTERFACE_ID)? {
            nft_state.get_info(clock.as_ref())?
        } else {
            return Err(NftError::InvalidNftContact.into());
        };

        let json_info =
            if tip6_interface.supports_interface(tip4_2::metadata_contract::INTERFACE_ID)? {
                Some(nft_state.get_json(clock.as_ref())?)
            } else {
                None
            };

        let contract_subscription = ContractSubscription::subscribe(
            clock.clone(),
            transport,
            nft_address.clone(),
            make_contract_state_handler(clock.clone(), &mut info.owner, &mut info.manager),
            make_transactions_handler(&handler),
        )
        .await?;

        handler.on_manager_changed(info.manager.clone());
        handler.on_owner_changed(info.owner.clone());

        Ok(Self {
            address: nft_address.clone(),
            collection_address: info.collection,
            owner: info.owner,
            manager: info.manager,
            json_info,
            contract_subscription,
            //handler,
        })
    }

    pub fn contract_subscription(&self) -> &ContractSubscription {
        &self.contract_subscription
    }

    pub fn address(&self) -> &MsgAddressInt {
        &self.address
    }

    pub fn collection_address(&self) -> &MsgAddressInt {
        &self.collection_address
    }

    pub fn owner(&self) -> &MsgAddressInt {
        &self.owner
    }

    pub fn manager(&self) -> &MsgAddressInt {
        &self.manager
    }

    pub fn metadata(&self) -> &Option<String> {
        &self.json_info
    }

    pub fn prepare_transfer(
        &self,
        to: MsgAddressInt,
        send_gas_to: MsgAddressInt,
        callbacks: BTreeMap<String, NftCallbackPayload>,
    ) -> Result<InternalMessage> {
        const ATTACHED_AMOUNT: u64 = 1_000_000_000; // 1 TON
        let (function, input) = MessageBuilder::new(nft_contract::transfer())
            .arg(to)
            .arg(send_gas_to)
            .arg(pack(callbacks))
            .build();

        let body = function.encode_internal_input(&input)?.into();

        Ok(InternalMessage {
            source: Some(self.owner.clone()),
            destination: self.address().clone(),
            amount: ATTACHED_AMOUNT,
            bounce: true,
            body,
        })
    }

    pub fn prepare_change_manager(
        &self,
        new_manager: MsgAddressInt,
        send_gas_to: MsgAddressInt,
        callbacks: BTreeMap<String, NftCallbackPayload>,
    ) -> Result<InternalMessage> {
        const ATTACHED_AMOUNT: u64 = 1_000_000_000; // 1 TON
        let (function, input) = MessageBuilder::new(nft_contract::change_manager())
            .arg(new_manager)
            .arg(send_gas_to)
            .arg(pack(callbacks))
            .build();

        let body = function.encode_internal_input(&input)?.into();

        Ok(InternalMessage {
            source: Some(self.owner.clone()),
            destination: self.address().clone(),
            amount: ATTACHED_AMOUNT,
            bounce: true,
            body,
        })
    }

    pub fn prepare_change_owner(
        &self,
        new_owner: MsgAddressInt,
        send_gas_to: MsgAddressInt,
        callbacks: BTreeMap<String, NftCallbackPayload>,
    ) -> Result<InternalMessage> {
        const ATTACHED_AMOUNT: u64 = 1_000_000_000; // 1 TON
        let (function, input) = MessageBuilder::new(nft_contract::change_owner())
            .arg(new_owner)
            .arg(send_gas_to)
            .arg(pack(callbacks))
            .build();

        let body = function.encode_internal_input(&input)?.into();

        Ok(InternalMessage {
            source: Some(self.owner.clone()),
            destination: self.address().clone(),
            amount: ATTACHED_AMOUNT,
            bounce: true,
            body,
        })
    }
}

// pub trait NftSubscription: Send + Sync {
//     fn on_transfer_completed(&self);
//
//     /// Called every time new transactions are detected.
//     /// - When new block found
//     /// - When manually requesting the latest transactions (can be called several times)
//     /// - When preloading transactions
//     fn on_transactions_found(
//         &self,
//         transactions: Vec<TransactionWithData<TokenWalletTransaction>>,
//         batch_info: TransactionsBatchInfo,
//     );
// }

// fn make_contract_state_handler(
//     clock: Arc<dyn Clock>,
//     version: TokenWalletVersion,
//     balance: &'_ mut BigUint,
// ) -> impl FnMut(&RawContractState) + '_ {
//     move |contract_state| {
//         if let RawContractState::Exists(state) = contract_state {
//             if let Ok(new_balance) =
//             TokenWalletContractState(state).get_balance(clock.as_ref(), version)
//             {
//                 *balance = new_balance;
//             }
//         }
//     }
// }

pub trait NftSubscriptionHandler: Send + Sync {
    fn on_manager_changed(&self, owner: MsgAddressInt);

    fn on_owner_changed(&self, manager: MsgAddressInt);

    /// Called every time new transactions are detected.
    /// - When new block found
    /// - When manually requesting the latest transactions (can be called several times)
    /// - When preloading transactions
    fn on_transactions_found(
        &self,
        transactions: Vec<TransactionWithData<NftTransaction>>,
        batch_info: TransactionsBatchInfo,
    );
}

fn make_contract_state_handler<'a>(
    clock: Arc<dyn Clock>,
    owner: &'a mut MsgAddressInt,
    manager: &'a mut MsgAddressInt,
) -> impl FnMut(&RawContractState) + 'a {
    move |contract_state| {
        if let RawContractState::Exists(state) = contract_state {
            if let Ok(info) = NftContractState(state).get_info(clock.as_ref()) {
                *owner = info.owner;
                *manager = info.manager
            }
        }
    }
}

fn make_transactions_handler<T>(
    handler: &'_ T,
) -> impl FnMut(Vec<RawTransaction>, TransactionsBatchInfo) + '_
where
    T: AsRef<dyn NftSubscriptionHandler>,
{
    move |transactions, batch_info| {
        let transactions = transactions
            .into_iter()
            .filter_map(
                |transaction| match transaction.data.description.read_struct().ok()? {
                    ton_block::TransactionDescr::Ordinary(description) => {
                        let data = parse_nft_transaction(&transaction.data, &description);

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

#[derive(Debug)]
pub struct CollectionContractState<'a>(pub &'a ExistingContract);

impl<'a> CollectionContractState<'a> {
    fn check_collection_supported_interface(
        &self,
        clock: &dyn Clock,
    ) -> Result<Option<NftVersion>> {
        let ctx = self.0.as_context(clock);
        let tip6_interface = tip6::SidContract(ctx);
        if tip6_interface.supports_interface(tip4_3::collection_contract::INTERFACE_ID)? {
            return Ok(Some(NftVersion::Tip4_3));
        }

        if tip6_interface.supports_interface(tip4_1::collection_contract::INTERFACE_ID)? {
            return Ok(Some(NftVersion::Tip4_1));
        }

        Ok(None)
    }

    fn resolve_collection_index_code(&self, clock: &dyn Clock) -> Result<ton_types::Cell> {
        let ctx = self.0.as_context(clock);
        let collection = tip4_3::CollectionContract(ctx);
        Ok(collection.index_code()?)
    }
    fn get_collection_code_hash(&self, owner: &MsgAddressInt, code_index: Cell) -> Result<UInt256> {
        let mut builder = BuilderData::new();

        let owner_cell = owner.serialize()?;
        let collection_cell = self.0.account.addr.serialize()?;

        builder.append_raw(collection_cell.data(), collection_cell.bit_length())?;
        builder.append_raw(owner_cell.data(), owner_cell.bit_length())?;

        let mut nft = BuilderData::new();
        nft.append_raw(NFT_STAMP, 24)?;

        builder.append_reference_cell(nft.into_cell()?);

        let salt = builder.into_cell()?;

        //let b64_cell = base64::encode(&ton_types::cells_serialization::serialize_toc(&salt)?);
        //println!("base64_salt: {}", &b64_cell);

        let cell = nekoton_abi::set_cell_salt(salt, code_index)?;
        Ok(cell.hash(0))
    }
}

#[derive(Debug)]
pub struct NftContractState<'a>(pub &'a ExistingContract);

impl<'a> NftContractState<'a> {
    fn get_json(&self, clock: &dyn Clock) -> Result<String> {
        let ctx = self.0.as_context(clock);
        let tip4_2_interface = tip4_2::MetadataContract(ctx);
        Ok(tip4_2_interface.get_json()?)
    }

    fn get_info(&self, clock: &dyn Clock) -> Result<GetInfoOutputs> {
        let ctx = self.0.as_context(clock);
        let tip4_1_interface = tip4_1::NftContract(ctx);
        Ok(tip4_1_interface.get_info()?)
    }
}

#[derive(Debug)]
pub struct IndexContractState<'a>(pub &'a ExistingContract);

impl<'a> IndexContractState<'a> {
    async fn get_info(&self, clock: &dyn Clock) -> Result<IndexGetInfoOutputs> {
        let ctx = self.0.as_context(clock);
        let index_interface = nft_index::IndexContract(ctx);
        Ok(index_interface.get_info()?)
    }
}

#[derive(thiserror::Error, Debug)]
enum NftError {
    #[error("Unsupported interface version")]
    UnsupportedInterfaceVersion,
    #[error("Invalid collection contract")]
    InvalidCollectionContract,
    #[error("Invalid nft contract")]
    InvalidNftContact,
    #[error("Contract does not exist")]
    ContractNotExist,
}
