pub mod rpc {
    include!(concat!(env!("OUT_DIR"), "/rpc.rs"));
}

pub mod models;
pub mod utils;

pub use prost;

use ton_types::UInt256;
use prost::bytes::Bytes;

use crate::rpc::response::get_contract_state::contract_state;

impl From<contract_state::GenTimings> for nekoton_abi::GenTimings {
    fn from(t: contract_state::GenTimings) -> Self {
        match t {
            contract_state::GenTimings::Known(known) => Self::Known {
                gen_lt: known.gen_lt,
                gen_utime: known.gen_utime,
            },
            contract_state::GenTimings::Unknown(()) => Self::Unknown,
        }
    }
}

impl From<nekoton_abi::GenTimings> for contract_state::GenTimings {
    fn from(t: nekoton_abi::GenTimings) -> Self {
        match t {
            nekoton_abi::GenTimings::Known { gen_lt, gen_utime } => {
                contract_state::GenTimings::Known(contract_state::Known { gen_lt, gen_utime })
            }
            nekoton_abi::GenTimings::Unknown => contract_state::GenTimings::Unknown(()),
        }
    }
}

impl From<contract_state::LastTransactionId> for nekoton_abi::LastTransactionId {
    fn from(t: contract_state::LastTransactionId) -> Self {
        match t {
            contract_state::LastTransactionId::Exact(contract_state::Exact { lt, hash }) => {
                Self::Exact(nekoton_abi::TransactionId {
                    lt,
                    hash: UInt256::from_slice(hash.as_ref()),
                })
            }
            contract_state::LastTransactionId::Inexact(contract_state::Inexact { latest_lt }) => {
                Self::Inexact { latest_lt }
            }
        }
    }
}

impl From<nekoton_abi::LastTransactionId> for contract_state::LastTransactionId {
    fn from(t: nekoton_abi::LastTransactionId) -> Self {
        match t {
            nekoton_abi::LastTransactionId::Exact(nekoton_abi::TransactionId { lt, hash }) => {
                Self::Exact(contract_state::Exact {
                    lt,
                    hash: Bytes::from(hash.into_vec()),
                })
            }
            nekoton_abi::LastTransactionId::Inexact { latest_lt } => {
                Self::Inexact(contract_state::Inexact { latest_lt })
            }
        }
    }
}
