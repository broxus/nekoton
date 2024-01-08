use std::collections::hash_map::{self, HashMap};
use std::sync::Arc;

use anyhow::Result;
use nekoton_contracts::dens;
use nekoton_utils::Clock;
use parking_lot::RwLock;
use quick_cache::sync::Cache;
use ton_block::MsgAddressInt;

use crate::transport::models::{ExistingContract, RawContractState};
use crate::transport::Transport;

/// `DeNS` domains collection
#[derive(Default)]
pub struct Dens {
    tld: RwLock<HashMap<String, Arc<DensTld>>>,
    contract_address_cache: Option<Cache<String, MsgAddressInt>>,
}

impl Dens {
    pub fn builder(clock: Arc<dyn Clock>, transport: Arc<dyn Transport>) -> DensBuilder {
        DensBuilder::new(clock, transport)
    }

    pub fn add_tld(&self, tld: Arc<DensTld>) -> Result<()> {
        if !validate_address(tld.path()) {
            return Err(DensError::InvalidPath.into());
        }

        match self.tld.write().entry(tld.path.clone()) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(tld);
                Ok(())
            }
            hash_map::Entry::Occupied(_) => Err(DensError::DuplicateTld.into()),
        }
    }

    pub async fn remove_tld(&self, path: &str) -> Option<Arc<DensTld>> {
        self.tld.write().remove(path)
    }

    pub async fn try_resolve_contract_address(&self, path: &str) -> Result<Option<MsgAddressInt>> {
        if !validate_address(path) {
            return Err(DensError::InvalidPath.into());
        }

        if let Some(contract_address_cache) = &self.contract_address_cache {
            if let Some(address) = contract_address_cache.get(path) {
                return Ok(Some(address.clone()));
            }
        }

        let address = self
            .find_tld(path)?
            .try_resolve_contract_address(path)
            .await?;

        if let Some(address) = &address {
            if let Some(contract_address_cache) = &self.contract_address_cache {
                contract_address_cache.insert(path.to_owned(), address.clone());
            }
        }

        Ok(address)
    }

    pub async fn try_resolve(&self, path: &str, record: u32) -> Result<ResolvedValue> {
        if !validate_address(path) {
            return Err(DensError::InvalidPath.into());
        }

        self.find_tld(path)?.try_resolve(path, record).await
    }

    pub fn reset_cache(&self) {
        if let Some(contract_address_cache) = &self.contract_address_cache {
            contract_address_cache.clear();
        }
    }

    fn find_tld(&self, path: &str) -> Result<Arc<DensTld>> {
        match path.rsplit_once('.') {
            Some((_, tld)) => {
                let state = self.tld.read();
                let tld = state.get(tld).cloned();
                tld.ok_or_else(|| DensError::TldNotFound.into())
            }
            None => Err(DensError::InvalidPath.into()),
        }
    }
}

pub struct DensBuilder {
    clock: Arc<dyn Clock>,
    transport: Arc<dyn Transport>,
    dens: Dens,
}

impl DensBuilder {
    pub fn new(clock: Arc<dyn Clock>, transport: Arc<dyn Transport>) -> Self {
        Self {
            clock,
            transport,
            dens: Default::default(),
        }
    }

    pub async fn register(self, tld_address: &MsgAddressInt) -> Result<Self> {
        let tld = DensTld::new(self.clock.clone(), self.transport.clone(), tld_address).await?;
        self.dens.add_tld(Arc::new(tld))?;
        Ok(self)
    }

    pub fn with_contract_address_cache(mut self, capacity: usize) -> Self {
        self.dens.contract_address_cache = Some(Cache::new(capacity));
        self
    }

    pub fn build(self) -> Dens {
        self.dens
    }
}

/// `DeNS` Top Level Domain
pub struct DensTld {
    clock: Arc<dyn Clock>,
    transport: Arc<dyn Transport>,
    path: String,
    state: ExistingContract,
}

impl DensTld {
    pub async fn new(
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        address: &MsgAddressInt,
    ) -> Result<Self> {
        let state = match transport.get_contract_state(address).await? {
            RawContractState::Exists(state) => state,
            RawContractState::NotExists { .. } => return Err(DensError::InvalidTldContract.into()),
        };
        let path = dens::RootContract(state.as_context(clock.as_ref())).get_path()?;

        Ok(Self {
            clock,
            transport,
            path,
            state,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub async fn try_resolve_contract_address(&self, path: &str) -> Result<Option<MsgAddressInt>> {
        match self.get_domain_state(path).await? {
            Some(domain) => dens::DomainContract(domain.as_context(self.clock.as_ref()))
                .query::<dens::TargetAddressRecord>(),
            None => Ok(None),
        }
    }

    pub async fn try_resolve_adnl_address(&self, path: &str) -> Result<Option<ton_types::UInt256>> {
        match self.get_domain_state(path).await? {
            Some(domain) => dens::DomainContract(domain.as_context(self.clock.as_ref()))
                .query::<dens::AdnlAddressRecord>(),
            None => Ok(None),
        }
    }

    pub async fn try_resolve(&self, path: &str, record: u32) -> Result<ResolvedValue> {
        match self.get_domain_state(path).await? {
            Some(domain) => match dens::DomainContract(domain.as_context(self.clock.as_ref()))
                .query_raw(record)?
            {
                Some(value) => Ok(ResolvedValue::Found(value)),
                None => Ok(ResolvedValue::RecordNotFound),
            },
            None => Ok(ResolvedValue::DomainNotFound),
        }
    }

    async fn get_domain_state(&self, path: &str) -> Result<Option<ExistingContract>> {
        let address =
            dens::RootContract(self.state.as_context(self.clock.as_ref())).resolve(path)?;
        Ok(self
            .transport
            .get_contract_state(&address)
            .await?
            .into_contract())
    }
}

pub fn validate_address(path: &str) -> bool {
    let mut segment_start = 0;
    let mut segment_end = 0;
    for (pos, byte) in path.as_bytes().iter().enumerate() {
        match *byte {
            b'.' => {
                if segment_start == segment_end {
                    return false;
                }
                segment_start = pos + 1;
                segment_end = segment_start;
                continue;
            }
            b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'-' => {
                segment_end = pos + 1;
            }
            _ => return false,
        }
    }
    segment_start != segment_end
}

#[derive(Debug, Clone)]
pub enum ResolvedValue {
    Found(ton_types::Cell),
    RecordNotFound,
    DomainNotFound,
}

#[derive(thiserror::Error, Debug)]
enum DensError {
    #[error("Invalid TLD contract")]
    InvalidTldContract,
    #[error("Duplicate TLD")]
    DuplicateTld,
    #[error("TLD not found")]
    TldNotFound,
    #[error("Invalid path")]
    InvalidPath,
}
