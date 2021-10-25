use crate::traits::TrustMe;

pub trait Clock: Send + Sync {
    fn now_sec_u64(&self) -> u64;
    fn now_ms_f64(&self) -> f64;
    fn now_ms_u64(&self) -> u64;
}

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
    offset_as_sec: u64,
    offset_as_ms: u64,
}

impl ClockWithOffset {
    pub fn new(offset_ms: u64) -> Self {
        let mut clock = Self::default();
        clock.update_offset(offset_ms);
        clock
    }

    pub fn update_offset(&mut self, offset_ms: u64) {
        self.offset_as_sec = offset_ms / 1000;
        self.offset_as_ms = offset_ms;
    }

    pub fn offset_ms(&self) -> u64 {
        self.offset_as_ms
    }
}

impl Clock for ClockWithOffset {
    fn now_sec_u64(&self) -> u64 {
        self.offset_as_sec + now_sec_u64()
    }

    fn now_ms_f64(&self) -> f64 {
        self.offset_as_ms as f64 + now_ms_f64()
    }

    fn now_ms_u64(&self) -> u64 {
        self.offset_as_ms + now_ms_u64()
    }
}

#[cfg(all(target_arch = "wasm32", feature = "web"))]
pub fn now_sec_u64() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

#[cfg(not(all(target_arch = "wasm32", feature = "web")))]
pub fn now_sec_u64() -> u64 {
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
