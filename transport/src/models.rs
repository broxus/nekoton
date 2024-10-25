use nekoton_utils::time::now_sec_u64;
use serde::{Deserialize, Serialize};

const MC_ACCEPTABLE_TIME_DIFF: u64 = 120;
const ACCEPTABLE_BLOCKS_DIFF: u32 = 500;
const ACCEPTABLE_NODE_BLOCK_INSERT_TIME: u64 = 240;

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Timings {
    pub last_mc_block_seqno: u32,
    pub last_mc_utime: u32,
    pub mc_time_diff: i64,
    pub smallest_known_lt: Option<u64>,
}

impl Timings {
    pub fn is_reliable(&self) -> bool {
        // just booted up
        if self == &Self::default() {
            return false;
        }

        let acceptable_time = (now_sec_u64() - ACCEPTABLE_NODE_BLOCK_INSERT_TIME) as u32;

        // TODO: clarify how is correct
        self.mc_time_diff.unsigned_abs() < MC_ACCEPTABLE_TIME_DIFF
            && self.last_mc_block_seqno < ACCEPTABLE_BLOCKS_DIFF
            && self.last_mc_utime > acceptable_time
    }
}

impl PartialOrd for Timings {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timings {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.mc_time_diff.cmp(&other.mc_time_diff)
    }
}