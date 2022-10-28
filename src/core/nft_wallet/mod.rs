use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use nekoton_abi::MessageBuilder;
use nekoton_contracts::tip4_1::nft_contract::{self, GetInfoOutputs, NftCallbackPayload};
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

pub struct NftCollection {
    transport: Arc<dyn Transport>,
    collection_address: MsgAddressInt,
    state: ExistingContract,
    index_code: Cell,
    json_info: Option<String>,
}

impl NftCollection {
    pub async fn new(
        clock: &dyn Clock,
        transport: Arc<dyn Transport>,
        collection_address: MsgAddressInt,
    ) -> Result<NftCollection> {
        let state = match transport.get_contract_state(&collection_address).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists => return Err(NftError::ContractNotExist.into()),
        };

        let contract = CollectionContractState(&state);

        let interfaces = contract.check_collection_supported_interfaces(clock)?;
        if !interfaces.tip4_3 {
            return Err(NftError::InvalidCollectionContract.into());
        }

        let index_code = contract.resolve_collection_index_code(clock)?;

        let json_info = interfaces
            .tip4_2
            .then(|| tip4_2::MetadataContract(state.as_context(clock)).get_json())
            .transpose()?;

        Ok(NftCollection {
            transport,
            collection_address,
            state,
            index_code,
            json_info,
        })
    }

    pub fn collection_address(&self) -> &MsgAddressInt {
        &self.collection_address
    }

    pub fn index_code(&self) -> &Cell {
        &self.index_code
    }

    pub fn json_info(&self) -> &Option<String> {
        &self.json_info
    }

    pub fn compute_collection_code_hash(&self, owner: &MsgAddressInt) -> Result<UInt256> {
        CollectionContractState(&self.state)
            .get_collection_code_hash(owner, self.index_code.clone())
    }

    pub async fn get_nft_index_contracts(
        &self,
        owner: &MsgAddressInt,
        limit: u8,
        continuation: Option<MsgAddressInt>,
    ) -> Result<Vec<MsgAddressInt>> {
        let code_hash = self.compute_collection_code_hash(owner)?;
        self.transport
            .get_accounts_by_code_hash(&code_hash, limit, &continuation)
            .await
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

        let version = match nft_state.check_supported_interface(clock.as_ref())? {
            Some(version) => version,
            None => return Err(NftError::InvalidNftContact.into()),
        };

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
            &mut make_contract_state_handler(
                clock.as_ref(),
                &mut info.owner,
                &mut info.manager,
                None,
            ),
            Some(&mut make_transactions_handler(handler.as_ref())),
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
        callbacks: BTreeMap<MsgAddressInt, NftCallbackPayload>,
    ) -> Result<InternalMessage> {
        const ATTACHED_AMOUNT: u64 = 1_000_000_000; // 1 TON
        let (function, input) = MessageBuilder::new(nft_contract::transfer())
            .arg(to)
            .arg(send_gas_to)
            .arg(callbacks)
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
        callbacks: BTreeMap<MsgAddressInt, NftCallbackPayload>,
    ) -> Result<InternalMessage> {
        const ATTACHED_AMOUNT: u64 = 1_000_000_000; // 1 TON
        let (function, input) = MessageBuilder::new(nft_contract::change_manager())
            .arg(new_manager)
            .arg(send_gas_to)
            .arg(callbacks)
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
        callbacks: BTreeMap<MsgAddressInt, NftCallbackPayload>,
    ) -> Result<InternalMessage> {
        const ATTACHED_AMOUNT: u64 = 1_000_000_000; // 1 TON
        let (function, input) = MessageBuilder::new(nft_contract::change_owner())
            .arg(new_owner)
            .arg(send_gas_to)
            .arg(callbacks)
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
        let handler = self.handler.as_ref();

        self.contract_subscription
            .refresh(
                &mut make_contract_state_handler(
                    self.clock.as_ref(),
                    &mut self.owner,
                    &mut self.manager,
                    Some(handler),
                ),
                &mut make_transactions_handler(handler),
                &mut make_message_sent_handler(handler),
                &mut make_message_expired_handler(handler),
            )
            .await
    }

    pub async fn preload_transactions(&mut self, from_lt: u64) -> Result<()> {
        let handler = self.handler.as_ref();
        self.contract_subscription
            .preload_transactions(from_lt, &mut make_transactions_handler(handler))
            .await
    }
}

pub trait NftSubscriptionHandler: Send + Sync {
    /// Called when found transaction which is relative with one of the pending transactions
    fn on_message_sent(
        &self,
        pending_transaction: PendingTransaction,
        transaction: Option<Transaction>,
    );

    /// Called when no transactions produced for the specific message before some expiration time
    fn on_message_expired(&self, pending_transaction: PendingTransaction);

    fn on_manager_changed(&self, manager: MsgAddressInt) {
        let _ = manager;
    }

    fn on_owner_changed(&self, owner: MsgAddressInt) {
        let _ = owner;
    }

    /// Called every time new transactions are detected.
    /// - When new block found
    /// - When manually requesting the latest transactions (can be called several times)
    /// - When preloading transactions
    fn on_transactions_found(
        &self,
        transactions: Vec<TransactionWithData<NftTransaction>>,
        batch_info: TransactionsBatchInfo,
    ) {
        let _ = transactions;
        let _ = batch_info;
    }
}

fn make_contract_state_handler<'a>(
    clock: &'a dyn Clock,
    owner: &'a mut MsgAddressInt,
    manager: &'a mut MsgAddressInt,
    handler: Option<&'a dyn NftSubscriptionHandler>,
) -> impl FnMut(&RawContractState) + 'a {
    move |contract_state| {
        if let RawContractState::Exists(state) = contract_state {
            if let Ok(info) = NftContractState(state).get_info(clock) {
                let mut owner_changed = false;
                if owner != &info.owner {
                    *owner = info.owner;
                    owner_changed = true;
                }

                let mut manager_changed = false;
                if manager != &info.manager {
                    *manager = info.manager;
                    manager_changed = true;
                }

                if let Some(handler) = handler {
                    if owner_changed {
                        handler.on_owner_changed(owner.clone());
                    }
                    if manager_changed {
                        handler.on_manager_changed(manager.clone());
                    }
                }
            }
        }
    }
}

fn make_transactions_handler(
    handler: &'_ dyn NftSubscriptionHandler,
) -> impl FnMut(Vec<RawTransaction>, TransactionsBatchInfo) + '_ {
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

        handler.on_transactions_found(transactions, batch_info)
    }
}

fn make_message_sent_handler(
    handler: &'_ dyn NftSubscriptionHandler,
) -> impl FnMut(PendingTransaction, RawTransaction) + '_ {
    move |pending_transaction, transaction| {
        let transaction = Transaction::try_from((transaction.hash, transaction.data)).ok();
        handler.on_message_sent(pending_transaction, transaction);
    }
}

fn make_message_expired_handler(
    handler: &'_ dyn NftSubscriptionHandler,
) -> impl FnMut(PendingTransaction) + '_ {
    move |pending_transaction| handler.on_message_expired(pending_transaction)
}

#[derive(Debug)]
pub struct CollectionContractState<'a>(pub &'a ExistingContract);

impl<'a> CollectionContractState<'a> {
    pub fn check_collection_supported_interfaces(
        &self,
        clock: &dyn Clock,
    ) -> Result<CollectionInterfaces> {
        let ctx = self.0.as_context(clock);
        let tip6_interface = tip6::SidContract(ctx);

        let mut result = CollectionInterfaces::default();

        if tip6_interface.supports_interface(tip4_3::collection_contract::INTERFACE_ID)? {
            result.tip4_3 = true;
            result.tip4_2 =
                tip6_interface.supports_interface(tip4_2::metadata_contract::INTERFACE_ID)?;
        }

        Ok(result)
    }

    pub fn resolve_collection_index_code(&self, clock: &dyn Clock) -> Result<Cell> {
        let ctx = self.0.as_context(clock);
        tip4_3::CollectionContract(ctx).index_code()
    }

    pub fn get_collection_code_hash(
        &self,
        owner: &MsgAddressInt,
        code_index: Cell,
    ) -> Result<UInt256> {
        let mut builder = BuilderData::new();

        let owner_cell = owner.serialize()?;
        let collection_cell = self.0.account.addr.serialize()?;

        builder.append_raw(collection_cell.data(), collection_cell.bit_length())?;
        builder.append_raw(owner_cell.data(), owner_cell.bit_length())?;

        let mut nft = BuilderData::new();
        nft.append_raw(NFT_STAMP, 24)?;

        builder.append_reference_cell(nft.into_cell()?);

        let salt = builder.into_cell()?;

        let cell = nekoton_abi::set_code_salt(code_index, salt)?;
        Ok(cell.hash(0))
    }
}

#[derive(Copy, Clone, Default)]
pub struct CollectionInterfaces {
    pub tip4_3: bool,
    pub tip4_2: bool,
}

#[derive(Debug)]
pub struct NftContractState<'a>(pub &'a ExistingContract);

impl<'a> NftContractState<'a> {
    pub fn check_supported_interface(&self, clock: &dyn Clock) -> Result<Option<NftVersion>> {
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

    pub fn get_json(&self, clock: &dyn Clock) -> Result<String> {
        let ctx = self.0.as_context(clock);
        let tip4_2_interface = tip4_2::MetadataContract(ctx);
        tip4_2_interface.get_json()
    }

    pub fn get_info(&self, clock: &dyn Clock) -> Result<GetInfoOutputs> {
        let ctx = self.0.as_context(clock);
        let tip4_1_interface = tip4_1::NftContract(ctx);
        tip4_1_interface.get_info()
    }
}

#[derive(Debug)]
pub struct IndexContractState<'a>(pub &'a ExistingContract);

impl<'a> IndexContractState<'a> {
    pub async fn get_info(&self, clock: &dyn Clock) -> Result<IndexGetInfoOutputs> {
        let ctx = self.0.as_context(clock);
        let index_interface = tip4_3::IndexContract(ctx);
        index_interface.get_info()
    }
}

#[derive(thiserror::Error, Debug)]
enum NftError {
    #[error("Invalid collection contract")]
    InvalidCollectionContract,
    #[error("Invalid nft contract")]
    InvalidNftContact,
    #[error("Contract does not exist")]
    ContractNotExist,
}
