use serde::Serialize;
use ton_block::MsgAddressInt;

#[derive(Serialize)]
pub struct RawTransactionRequest {
    pub limit: u64,

    #[serde(default, with = "serde_optional_amount")]
    pub last_transaction_lt: Option<u64>,

    #[serde(with = "serde_split_address")]
    pub account: SplitAddress,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SplitAddress {
    pub workchain: i8,
    pub address: Vec<u8>,
}

impl From<ton_block::MsgAddressInt> for SplitAddress {
    fn from(val: MsgAddressInt) -> Self {
        Self {
            workchain: val.workchain_id() as i8,
            address: val.address().get_bytestring(0),
        }
    }
}

pub mod serde_split_address {
    use serde::Serialize;

    use super::SplitAddress;

    pub fn serialize<S>(address: &SplitAddress, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        format!("{}:{}", address.workchain, hex::encode(&address.address)).serialize(serializer)
    }
}

pub mod serde_optional_amount {
    use serde::Serialize;

    pub fn serialize<S>(amount: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        amount.map(|x| x.to_string()).serialize(serializer)
    }
}
