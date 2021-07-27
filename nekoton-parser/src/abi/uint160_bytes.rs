use num_bigint::BigUint;
use ton_abi::TokenValue;

use super::{ContractResult, UnpackerError};

pub fn unpack(value: &TokenValue) -> ContractResult<BigUint> {
    match value {
        TokenValue::Uint(data) => {
            let mut result = [0u8; 20];
            let data = data.number.to_bytes_be();
            if data.len() > 20 {
                return Err(UnpackerError::InvalidAbi);
            }

            let offset = result.len() - data.len();
            result[offset..20].copy_from_slice(&data);

            Ok(BigUint::from_bytes_be(&result))
        }
        _ => Err(UnpackerError::InvalidAbi),
    }
}
