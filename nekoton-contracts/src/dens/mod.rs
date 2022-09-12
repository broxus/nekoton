use anyhow::Result;
use nekoton_abi::*;
use ton_block::Deserializable;

use crate::RunLocalSimple;

pub mod domain_contract;
pub mod root_contract;

#[derive(Copy, Clone)]
pub struct RootContract<'a>(pub ExecutionContext<'a>);

impl RootContract<'_> {
    pub fn resolve<T>(&self, path: T) -> Result<ton_block::MsgAddressInt>
    where
        T: AsRef<str> + BuildTokenValue,
    {
        let inputs = [
            0u32.token_value().named("answerId"),
            path.token_value().named("path"),
        ];
        let result = self
            .0
            .run_local_responsible_simple(root_contract::resolve(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}

#[derive(Copy, Clone)]
pub struct DomainContract<'a>(pub ExecutionContext<'a>);

impl DomainContract<'_> {
    pub fn query<T>(&self) -> Result<Option<T::Value>>
    where
        T: CertificateRecord,
    {
        let value = match self.query_raw(T::RECORD_ID)? {
            Some(value) => value,
            None => return Ok(None),
        };
        <T::Value as Deserializable>::construct_from_cell(value).map(Some)
    }

    pub fn query_raw(&self, record: u32) -> Result<Option<ton_types::Cell>> {
        let inputs = [
            0u32.token_value().named("answerId"),
            record.token_value().named("key"),
        ];
        let Maybe(result) = self
            .0
            .run_local_responsible_simple(domain_contract::query(), &inputs)?
            .unpack_first()?;
        Ok(result)
    }
}

pub trait CertificateRecord {
    const RECORD_ID: u32;
    type Value: Deserializable;
}

#[derive(Copy, Clone, Debug)]
pub struct TargetAddressRecord;

impl CertificateRecord for TargetAddressRecord {
    const RECORD_ID: u32 = 0;
    type Value = ton_block::MsgAddressInt;
}

#[derive(Copy, Clone, Debug)]
pub struct AdnlAddressRecord;

impl CertificateRecord for AdnlAddressRecord {
    const RECORD_ID: u32 = 1;
    type Value = ton_types::UInt256;
}
