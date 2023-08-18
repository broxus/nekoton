use prost::bytes::Bytes;
use ton_types::UInt256;

use crate::rpc::response::get_contract_state::exists::{Exact, Inexact, LastTransactionId};
use crate::rpc::response::get_contract_state::not_exist::GenTimings;
use crate::rpc::response::get_contract_state::{NotExist, Timings};

impl From<GenTimings> for nekoton_abi::GenTimings {
    fn from(t: GenTimings) -> Self {
        match t {
            GenTimings::Known(known) => Self::Known {
                gen_lt: known.gen_lt,
                gen_utime: known.gen_utime,
            },
            GenTimings::Unknown(()) => Self::Unknown,
        }
    }
}

impl From<nekoton_abi::GenTimings> for GenTimings {
    fn from(t: nekoton_abi::GenTimings) -> Self {
        match t {
            nekoton_abi::GenTimings::Known { gen_lt, gen_utime } => {
                GenTimings::Known(Timings { gen_lt, gen_utime })
            }
            nekoton_abi::GenTimings::Unknown => GenTimings::Unknown(()),
        }
    }
}

impl From<nekoton_abi::GenTimings> for NotExist {
    fn from(t: nekoton_abi::GenTimings) -> Self {
        let get_timings = match t {
            nekoton_abi::GenTimings::Known { gen_lt, gen_utime } => {
                GenTimings::Known(Timings { gen_lt, gen_utime })
            }
            nekoton_abi::GenTimings::Unknown => GenTimings::Unknown(()),
        };

        Self {
            gen_timings: Some(get_timings),
        }
    }
}

impl From<Timings> for NotExist {
    fn from(t: Timings) -> Self {
        Self {
            gen_timings: Some(GenTimings::Known(Timings {
                gen_lt: t.gen_lt,
                gen_utime: t.gen_utime,
            })),
        }
    }
}

impl From<nekoton_abi::GenTimings> for Timings {
    fn from(t: nekoton_abi::GenTimings) -> Self {
        match t {
            nekoton_abi::GenTimings::Known { gen_lt, gen_utime } => Self { gen_lt, gen_utime },
            nekoton_abi::GenTimings::Unknown => Self::default(), // unreachable since everscale-rpc-server must set timings
        }
    }
}

impl From<Timings> for nekoton_abi::GenTimings {
    fn from(t: Timings) -> Self {
        Self::Known {
            gen_lt: t.gen_lt,
            gen_utime: t.gen_utime,
        }
    }
}

impl From<LastTransactionId> for nekoton_abi::LastTransactionId {
    fn from(t: LastTransactionId) -> Self {
        match t {
            LastTransactionId::Exact(Exact { lt, hash }) => {
                Self::Exact(nekoton_abi::TransactionId {
                    lt,
                    hash: UInt256::from_slice(hash.as_ref()),
                })
            }
            LastTransactionId::Inexact(Inexact { latest_lt }) => Self::Inexact { latest_lt },
        }
    }
}

impl From<nekoton_abi::LastTransactionId> for LastTransactionId {
    fn from(t: nekoton_abi::LastTransactionId) -> Self {
        match t {
            nekoton_abi::LastTransactionId::Exact(nekoton_abi::TransactionId { lt, hash }) => {
                Self::Exact(Exact {
                    lt,
                    hash: Bytes::from(hash.into_vec()),
                })
            }
            nekoton_abi::LastTransactionId::Inexact { latest_lt } => {
                Self::Inexact(Inexact { latest_lt })
            }
        }
    }
}
