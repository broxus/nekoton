use std::convert::TryInto;
use std::sync::atomic::{AtomicI64, Ordering};

pub trait Clock: Send + Sync {
    fn now_sec_u64(&self) -> u64;
    fn now_ms_f64(&self) -> f64;
    fn now_ms_u64(&self) -> u64;
}

#[derive(Copy, Clone, Debug)]
pub struct SimpleClock;

impl Clock for SimpleClock {
    #[inline]
    fn now_sec_u64(&self) -> u64 {
        now_sec_u64()
    }

    #[inline]
    fn now_ms_f64(&self) -> f64 {
        now_ms_f64()
    }

    #[inline]
    fn now_ms_u64(&self) -> u64 {
        now_ms_u64()
    }
}

#[derive(Default)]
pub struct ClockWithOffset {
    offset_as_sec: AtomicI64,
    offset_as_ms: AtomicI64,
}

impl ClockWithOffset {
    pub fn new(offset_ms: i64) -> Self {
        Self {
            offset_as_sec: AtomicI64::new(offset_ms / 1000),
            offset_as_ms: AtomicI64::new(offset_ms),
        }
    }

    pub fn update_offset(&self, offset_ms: i64) {
        self.offset_as_sec
            .store(offset_ms / 1000, Ordering::Release);
        self.offset_as_ms.store(offset_ms, Ordering::Release);
    }

    pub fn offset_ms(&self) -> i64 {
        self.offset_as_ms.load(Ordering::Acquire)
    }
}

impl Clock for ClockWithOffset {
    #[inline]
    fn now_sec_u64(&self) -> u64 {
        self.offset_as_sec
            .load(Ordering::Acquire)
            .saturating_add(now_sec_u64() as i64)
            .try_into()
            .unwrap_or_default()
    }

    #[inline]
    fn now_ms_f64(&self) -> f64 {
        self.offset_as_ms.load(Ordering::Acquire) as f64 + now_ms_f64()
    }

    #[inline]
    fn now_ms_u64(&self) -> u64 {
        self.offset_as_ms
            .load(Ordering::Acquire)
            .saturating_add(now_ms_u64() as i64)
            .try_into()
            .unwrap_or_default()
    }
}

#[derive(Copy, Clone, Default)]
pub struct ConstClock {
    time_as_sec: u64,
    time_as_ms: u64,
}

impl ConstClock {
    #[inline]
    pub const fn from_millis(millis: u64) -> Self {
        Self {
            time_as_sec: millis / 1000,
            time_as_ms: millis,
        }
    }

    #[inline]
    pub const fn from_secs(secs: u64) -> Self {
        Self {
            time_as_sec: secs,
            time_as_ms: secs * 1000,
        }
    }
}

impl Clock for ConstClock {
    #[inline]
    fn now_sec_u64(&self) -> u64 {
        self.time_as_sec
    }

    #[inline]
    fn now_ms_f64(&self) -> f64 {
        self.time_as_ms as f64
    }

    #[inline]
    fn now_ms_u64(&self) -> u64 {
        self.time_as_ms
    }
}

#[cfg(all(target_arch = "wasm32", feature = "web"))]
pub fn now_sec_u64() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

#[cfg(not(all(target_arch = "wasm32", feature = "web")))]
pub fn now_sec_u64() -> u64 {
    use crate::traits::TrustMe;
    use std::time::SystemTime;

    (SystemTime::now().duration_since(SystemTime::UNIX_EPOCH))
        .trust_me()
        .as_secs()
}

#[cfg(all(target_arch = "wasm32", feature = "web"))]
pub fn now_ms_f64() -> f64 {
    js_sys::Date::now()
}

#[cfg(not(all(target_arch = "wasm32", feature = "web")))]
pub fn now_ms_f64() -> f64 {
    use crate::traits::TrustMe;
    use std::time::SystemTime;

    (SystemTime::now().duration_since(SystemTime::UNIX_EPOCH))
        .trust_me()
        .as_secs_f64()
        * 1000.0
}

#[cfg(all(target_arch = "wasm32", feature = "web"))]
pub fn now_ms_u64() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(not(all(target_arch = "wasm32", feature = "web")))]
pub fn now_ms_u64() -> u64 {
    use crate::traits::TrustMe;
    use std::time::SystemTime;

    let duration = (SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)).trust_me();
    duration.as_secs() * 1000 + duration.subsec_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time() {
        println!("{}", now_sec_u64());
        println!("{}", now_ms_f64());
        println!("{}", now_ms_u64());
    }
}
