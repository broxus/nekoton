use std::cmp::Ordering;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ton_types::UInt256;

use nekoton_utils::*;

#[derive(Debug, Copy, Clone)]
pub enum GenTimings {
    /// There is no way to determine the point in time at which this specific state was obtained
    Unknown,
    /// There is a known point in time at which this specific state was obtained
    Known { gen_lt: u64, gen_utime: u32 },
}

impl Serialize for GenTimings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct GenTimingsHelper {
            #[serde(with = "serde_string")]
            gen_lt: u64,
            gen_utime: u32,
        }

        let (gen_lt, gen_utime) = match *self {
            Self::Unknown => (0, 0),
            Self::Known { gen_lt, gen_utime } => (gen_lt, gen_utime),
        };
        GenTimingsHelper { gen_lt, gen_utime }.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GenTimings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct GenTimingsHelper {
            gen_lt: String,
            gen_utime: u32,
        }

        let GenTimingsHelper { gen_lt, gen_utime } = GenTimingsHelper::deserialize(deserializer)?;
        let gen_lt = u64::from_str(&gen_lt).map_err(D::Error::custom)?;

        Ok(match (gen_lt, gen_utime) {
            (0, _) | (_, 0) => Self::Unknown,
            (gen_lt, gen_utime) => Self::Known { gen_lt, gen_utime },
        })
    }
}

impl Default for GenTimings {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Additional estimated lag for the pending message to be expired
pub const GEN_TIMINGS_ALLOWABLE_INTERVAL: u32 = 30;

impl GenTimings {
    pub fn current_utime(&self, clock: &dyn Clock) -> u32 {
        match *self {
            GenTimings::Unknown => {
                // TODO: split optimistic and pessimistic predictions for unknown timings
                clock.now_sec_u64() as u32 - GEN_TIMINGS_ALLOWABLE_INTERVAL
            }
            GenTimings::Known { gen_utime, .. } => gen_utime,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq)]
pub enum LastTransactionId {
    Exact(TransactionId),
    Inexact { latest_lt: u64 },
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

impl Serialize for LastTransactionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct LastTransactionIdHelper {
            is_exact: bool,
            lt: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            hash: Option<String>,
        }

        let (is_exact, lt, hash) = match self {
            Self::Exact(id) => (true, &id.lt, Some(id.hash.to_hex_string())),
            Self::Inexact { latest_lt } => (false, latest_lt, None),
        };

        LastTransactionIdHelper {
            is_exact,
            lt: lt.to_string(),
            hash,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LastTransactionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct LastTransactionIdHelper {
            is_exact: bool,
            lt: String,
            #[serde(default)]
            hash: Option<String>,
        }

        let LastTransactionIdHelper { is_exact, lt, hash } =
            LastTransactionIdHelper::deserialize(deserializer)?;

        let lt = u64::from_str(&lt).map_err(D::Error::custom)?;
        match (is_exact, hash) {
            (true, Some(hash)) => {
                let hash = UInt256::from_str(&hash).map_err(D::Error::custom)?;
                Ok(Self::Exact(TransactionId { lt, hash }))
            }
            (false, None) => Ok(Self::Inexact { latest_lt: lt }),
            _ => Err(D::Error::custom("invalid last transaction id")),
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
    #[serde(with = "serde_string")]
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
