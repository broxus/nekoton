use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use nekoton_abi::{MessageBuilder, TransactionId};
use nekoton_contracts::tip4_1::nft_contract;
use nekoton_contracts::tip4_1::nft_contract::*;
use nekoton_contracts::tip4_3::index_contract::IndexGetInfoOutputs;
use nekoton_contracts::*;
use nekoton_utils::Clock;
use ton_block::{MsgAddressInt, Serializable};
use ton_types::{BuilderData, Cell, UInt256};

use crate::core::models::{
    NftTransaction, NftVersion, PendingTransaction, Transaction, TransactionWithData,
    TransactionsBatchInfo,
};
use crate::core::parsing::parse_nft_transaction;
use crate::core::{ContractSubscription, InternalMessage};
use crate::transport::models::{ExistingContract, RawContractState, RawTransaction};
use crate::transport::Transport;

const NFT_STAMP: &[u8; 3] = b"nft";

#[derive(Debug)]
pub struct NftCollection {
    pub collection_address: MsgAddressInt,
    state: ExistingContract,
}

impl NftCollection {
    pub fn collection_address(&self) -> &MsgAddressInt {
        &self.collection_address
    }

    pub async fn get(
        transport: Arc<dyn Transport>,
        collection_address: MsgAddressInt,
    ) -> Result<NftCollection> {
        let state = match transport.get_contract_state(&collection_address).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists => return Err(NftError::ContractNotExist.into()),
        };

        Ok(NftCollection {
            collection_address,
            state,
        })
    }
    pub async fn get_collection_nfts(
        &self,
        clock: Arc<dyn Clock>,
        continuation: &Option<MsgAddressInt>,
    ) -> Result<Vec<MsgAddressInt>> {
        // let nfts = match CollectionContractState(&self.state)
        //     .check_collection_supported_interface(clock.as_ref())?
        // {
        //     Some(NftVersion::Tip4_3) => {
        //         // let index_code = CollectionContractState(&self.state)
        //         //     .resolve_collection_index_code(clock.as_ref())?;
        //         // let code_hash = CollectionContractState(&self.state)
        //         //     .get_collection_code_hash(&owner, index_code)?;
        //         // transport
        //         //     .get_accounts_by_code_hash(&code_hash, limit, continuation)
        //         //     .await?
        //         todo!()
        //     }
        //     None => return Err(NftError::InvalidCollectionContract.into()),
        //     _ => return Err(NftError::UnsupportedInterfaceVersion.into()),
        // };

        Ok(Default::default())
    }
}

pub struct Nft {
    clock: Arc<dyn Clock>,
    address: MsgAddressInt,
    collection_address: MsgAddressInt,
    owner: MsgAddressInt,
    manager: MsgAddressInt,
    version: NftVersion,
    json_info: Option<String>,
    contract_subscription: ContractSubscription,
    handler: Arc<dyn NftSubscriptionHandler>,
}

impl Nft {
    pub async fn subscribe_by_index_address(
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
        Nft::subscribe(&info.nft, transport, clock, handler).await
    }
    pub async fn subscribe_by_nft_address(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        address: &MsgAddressInt,
        handler: Arc<dyn NftSubscriptionHandler>,
    ) -> Result<Nft> {
        Nft::subscribe(address, transport, clock, handler).await
    }

    async fn subscribe(
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
        if let Some(version) = nft_state.check_supported_interface(clock.as_ref())? {
            let (mut info, json_metadata) = match version {
                NftVersion::Tip4_3 | NftVersion::Tip4_2 => (
                    nft_state.get_info(clock.as_ref())?,
                    Some(nft_state.get_json(clock.as_ref())?),
                ),
                NftVersion::Tip4_1 => (nft_state.get_info(clock.as_ref())?, None),
            };

            let contract_subscription = ContractSubscription::subscribe(
                clock.clone(),
                transport,
                nft_address.clone(),
                make_contract_state_handler(clock.as_ref(), &mut info.owner, &mut info.manager),
                make_transactions_handler(&handler),
            )
            .await?;

            handler.on_manager_changed(info.manager.clone());
            handler.on_owner_changed(info.owner.clone());

            Ok(Self {
                clock,
                address: nft_address.clone(),
                collection_address: info.collection,
                owner: info.owner,
                manager: info.manager,
                version,
                json_info: json_metadata,
                contract_subscription,
                handler,
            })
        } else {
            Err(NftError::InvalidNftContact.into())
        }
    }

    pub fn version(&self) -> &NftVersion {
        &self.version
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
        let (function, input) = MessageBuilder::new(transfer())
            .arg(to)
            .arg(send_gas_to)
            .arg(map_address_tuple::pack(callbacks))
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
        let (function, input) = MessageBuilder::new(change_manager())
            .arg(new_manager)
            .arg(send_gas_to)
            .arg(map_address_tuple::pack(callbacks))
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
            .arg(map_address_tuple::pack(callbacks))
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

    pub async fn send(
        &mut self,
        message: &ton_block::Message,
        expire_at: u32,
    ) -> Result<PendingTransaction> {
        self.contract_subscription.send(message, expire_at).await
    }

    pub async fn refresh(&mut self) -> Result<()> {
        self.contract_subscription
            .refresh(
                make_contract_state_handler(
                    self.clock.as_ref(),
                    &mut self.owner,
                    &mut self.manager,
                ),
                make_transactions_handler(&self.handler),
                make_message_sent_handler(&self.handler),
                make_message_expired_handler(&self.handler),
            )
            .await
    }

    pub async fn preload_transactions(&mut self, from: TransactionId) -> Result<()> {
        self.contract_subscription
            .preload_transactions(from, make_transactions_handler(&self.handler))
            .await
    }
}

pub trait NftSubscriptionHandler: Send + Sync {
    fn on_manager_changed(&self, owner: MsgAddressInt);

    fn on_owner_changed(&self, manager: MsgAddressInt);

    /// Called when found transaction which is relative with one of the pending transactions
    fn on_message_sent(
        &self,
        pending_transaction: PendingTransaction,
        transaction: Option<Transaction>,
    );

    /// Called every time new transactions are detected.
    /// - When new block found
    /// - When manually requesting the latest transactions (can be called several times)
    /// - When preloading transactions
    fn on_transactions_found(
        &self,
        transactions: Vec<TransactionWithData<NftTransaction>>,
        batch_info: TransactionsBatchInfo,
    );

    /// Called when no transactions produced for the specific message before some expiration time
    fn on_message_expired(&self, pending_transaction: PendingTransaction);
}

fn make_contract_state_handler<'a>(
    clock: &'a dyn Clock,
    owner: &'a mut MsgAddressInt,
    manager: &'a mut MsgAddressInt,
) -> impl FnMut(&RawContractState) + 'a {
    move |contract_state| {
        if let RawContractState::Exists(state) = contract_state {
            if let Ok(info) = NftContractState(state).get_info(clock) {
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

fn make_message_sent_handler<T>(
    handler: &'_ T,
) -> impl FnMut(PendingTransaction, RawTransaction) + '_
where
    T: AsRef<dyn NftSubscriptionHandler>,
{
    move |pending_transaction, transaction| {
        let transaction = Transaction::try_from((transaction.hash, transaction.data)).ok();
        handler
            .as_ref()
            .on_message_sent(pending_transaction, transaction);
    }
}

fn make_message_expired_handler<T>(handler: &'_ T) -> impl FnMut(PendingTransaction) + '_
where
    T: AsRef<dyn NftSubscriptionHandler>,
{
    move |pending_transaction| handler.as_ref().on_message_expired(pending_transaction)
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

        let cell = nekoton_abi::set_cell_salt(code_index, salt)?;
        Ok(cell.hash(0))
    }
}

#[derive(Debug)]
pub struct NftContractState<'a>(pub &'a ExistingContract);

impl<'a> NftContractState<'a> {
    fn check_supported_interface(&self, clock: &dyn Clock) -> Result<Option<NftVersion>> {
        let ctx = self.0.as_context(clock);
        let tip6_interface = tip6::SidContract(ctx);
        if tip6_interface.supports_interface(tip4_3::nft_contract::INTERFACE_ID)? {
            return Ok(Some(NftVersion::Tip4_3));
        }

        if tip6_interface.supports_interface(tip4_2::metadata_contract::INTERFACE_ID)? {
            return Ok(Some(NftVersion::Tip4_2));
        }

        if tip6_interface.supports_interface(tip4_1::nft_contract::INTERFACE_ID)? {
            return Ok(Some(NftVersion::Tip4_1));
        }

        Ok(None)
    }

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
        let index_interface = tip4_3::IndexContract(ctx);
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
