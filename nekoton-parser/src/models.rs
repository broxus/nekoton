use chrono::Utc;
use nekoton_utils::*;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use ton_types::UInt256;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum GenTimings {
    /// There is no way to determine the point in time at which this specific state was obtained
    Unknown,
    /// There is a known point in time at which this specific state was obtained
    Known {
        #[serde(with = "serde_u64")]
        gen_lt: u64,
        gen_utime: u32,
    },
}

impl Default for GenTimings {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Additional estimated lag for the pending message to be expired
pub const GEN_TIMINGS_ALLOWABLE_INTERVAL: u32 = 30;

impl GenTimings {
    pub fn current_utime(&self) -> u32 {
        match *self {
            GenTimings::Unknown => {
                // TODO: split optimistic and pessimistic predictions for unknown timings
                Utc::now().timestamp() as u32 - GEN_TIMINGS_ALLOWABLE_INTERVAL
            }
            GenTimings::Known { gen_utime, .. } => gen_utime,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type", content = "data")]
pub enum LastTransactionId {
    Exact(TransactionId),
    Inexact {
        #[serde(with = "serde_u64")]
        latest_lt: u64,
    },
}

impl LastTransactionId {
    /// Whether the exact id is known
    pub fn is_exact(&self) -> bool {
        matches!(self, Self::Exact(_))
    }

    /// Converts last transaction id into real or fake id
    pub fn to_transaction_id(self) -> TransactionId {
        match self {
            Self::Exact(id) => id,
            Self::Inexact { latest_lt } => TransactionId {
                lt: latest_lt,
                hash: Default::default(),
            },
        }
    }
}

impl PartialEq for LastTransactionId {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact(left), Self::Exact(right)) => left == right,
            (Self::Inexact { latest_lt: left }, Self::Inexact { latest_lt: right }) => {
                left == right
            }
            _ => false,
        }
    }
}

impl PartialOrd for LastTransactionId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LastTransactionId {
    fn cmp(&self, other: &Self) -> Ordering {
        let left = match self {
            Self::Exact(id) => &id.lt,
            Self::Inexact { latest_lt } => latest_lt,
        };
        let right = match other {
            Self::Exact(id) => &id.lt,
            Self::Inexact { latest_lt } => latest_lt,
        };
        left.cmp(right)
    }
}

#[derive(Debug, Copy, Clone, Eq, Serialize, Deserialize)]
pub struct TransactionId {
    #[serde(with = "serde_u64")]
    pub lt: u64,
    #[serde(with = "serde_uint256")]
    pub hash: UInt256,
}

impl PartialEq for TransactionId {
    fn eq(&self, other: &Self) -> bool {
        self.lt == other.lt
    }
}

impl PartialOrd for TransactionId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.lt.cmp(&other.lt)
    }
}
