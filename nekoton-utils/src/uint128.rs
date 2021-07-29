use std::fmt::{LowerHex, UpperHex};
use std::str::FromStr;
use ton_types::SliceData;

#[allow(clippy::derive_hash_xor_eq)]
#[derive(Clone, Default, PartialEq, Eq, Hash, Ord, PartialOrd, Copy)]
pub struct UInt128([u8; 16]);

impl PartialEq<SliceData> for UInt128 {
    fn eq(&self, other: &SliceData) -> bool {
        if other.remaining_bits() == 128 {
            return self.0 == other.get_bytestring(0).as_slice();
        }
        false
    }
}

impl PartialEq<UInt128> for &UInt128 {
    fn eq(&self, other: &UInt128) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<&UInt128> for UInt128 {
    fn eq(&self, other: &&UInt128) -> bool {
        self.0 == other.0
    }
}

impl UInt128 {
    pub fn is_zero(&self) -> bool {
        for b in &self.0 {
            if b != &0 {
                return false;
            }
        }
        true
    }

    pub fn as_slice(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex_string(self) -> String {
        hex::encode(self.0)
    }

    pub fn max() -> Self {
        UInt128([0xFF; 16])
    }

    pub const MIN: UInt128 = UInt128([0; 16]);
    pub const MAX: UInt128 = UInt128([0xFF; 16]);
}

impl FromStr for UInt128 {
    type Err = failure::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 32 {
            ton_types::fail!("invalid account ID string length (32 expected)")
        } else {
            let bytes = hex::decode(value)?;
            Ok(UInt128::from(bytes))
        }
    }
}

impl From<[u8; 16]> for UInt128 {
    fn from(data: [u8; 16]) -> Self {
        UInt128(data)
    }
}

impl From<UInt128> for [u8; 16] {
    fn from(data: UInt128) -> Self {
        data.0
    }
}

impl<'a> From<&'a UInt128> for &'a [u8; 16] {
    fn from(data: &'a UInt128) -> Self {
        &data.0
    }
}

impl<'a> From<&'a [u8; 16]> for UInt128 {
    fn from(data: &[u8; 16]) -> Self {
        UInt128(*data)
    }
}

impl From<&[u8]> for UInt128 {
    fn from(value: &[u8]) -> Self {
        let mut data = [0; 16];
        let len = std::cmp::min(value.len(), 16);
        let offset = 16 - len;
        (0..len).for_each(|i| data[i + offset] = value[i]);
        Self(data)
    }
}

impl From<Vec<u8>> for UInt128 {
    fn from(value: Vec<u8>) -> Self {
        UInt128::from(value.as_slice())
    }
}

impl std::fmt::Debug for UInt128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        LowerHex::fmt(self, f)
    }
}

impl std::fmt::Display for UInt128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UInt128[{:X?}]", self.as_slice())
    }
}

impl LowerHex for UInt128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl UpperHex for UInt128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        write!(f, "{}", hex::encode_upper(&self.0))
    }
}

impl AsRef<[u8]> for &UInt128 {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
