use std::collections::BTreeMap;
use std::str::FromStr;

use num_bigint::{BigInt, BigUint};
use num_traits::Num;

pub fn make_abi_tokens(tokens: &[ton_abi::Token]) -> anyhow::Result<serde_json::Value> {
    let mut object = serde_json::Map::with_capacity(tokens.len());
    for token in tokens {
        object.insert(token.name.clone(), make_abi_token_value(&token.value)?);
    }
    Ok(serde_json::Value::Object(object))
}

pub fn make_abi_token_value(value: &ton_abi::TokenValue) -> anyhow::Result<serde_json::Value> {
    Ok(match value {
        ton_abi::TokenValue::Uint(value) => serde_json::Value::String(value.number.to_string()),
        ton_abi::TokenValue::Int(value) => serde_json::Value::String(value.number.to_string()),
        ton_abi::TokenValue::VarInt(_, value) => serde_json::Value::String(value.to_string()),
        ton_abi::TokenValue::VarUint(_, value) => serde_json::Value::String(value.to_string()),
        ton_abi::TokenValue::Bool(value) => serde_json::Value::Bool(*value),
        ton_abi::TokenValue::Tuple(tokens) => make_abi_tokens(tokens)?,
        ton_abi::TokenValue::Array(_, values) | ton_abi::TokenValue::FixedArray(_, values) => {
            serde_json::Value::Array(
                values
                    .iter()
                    .map(make_abi_token_value)
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        ton_abi::TokenValue::Cell(value) => {
            let data = ton_types::serialize_toc(value)?;
            serde_json::Value::String(base64::encode(&data))
        }
        ton_abi::TokenValue::Map(_, _, values) => serde_json::Value::Array(
            values
                .iter()
                .map(|(key, value)| {
                    Result::<serde_json::Value, anyhow::Error>::Ok(serde_json::Value::Array(vec![
                        serde_json::Value::String(key.clone()),
                        make_abi_token_value(value)?,
                    ]))
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        ton_abi::TokenValue::Address(value) => serde_json::Value::String(value.to_string()),
        ton_abi::TokenValue::Bytes(value) | ton_abi::TokenValue::FixedBytes(value) => {
            serde_json::Value::String(base64::encode(value))
        }
        ton_abi::TokenValue::String(value) => serde_json::Value::String(value.clone()),
        ton_abi::TokenValue::Token(value) => serde_json::Value::String(value.0.to_string()),
        ton_abi::TokenValue::Time(value) => serde_json::Value::String(value.to_string()),
        &ton_abi::TokenValue::Expire(value) => serde_json::Value::Number(value.into()),
        ton_abi::TokenValue::PublicKey(value) => match value {
            Some(key) => serde_json::Value::String(hex::encode(key.as_bytes())),
            None => serde_json::Value::Null,
        },
        ton_abi::TokenValue::Optional(_, value) => match value {
            Some(value) => make_abi_token_value(value)?,
            None => serde_json::Value::Null,
        },
        ton_abi::TokenValue::Ref(value) => make_abi_token_value(value)?,
    })
}

pub fn parse_abi_tokens(
    params: &[ton_abi::Param],
    tokens: serde_json::Value,
) -> Result<Vec<ton_abi::Token>, TokensJsonError> {
    if params.is_empty() {
        return Ok(Vec::new());
    }

    let mut tokens = match tokens {
        serde_json::Value::Object(tokens) => tokens,
        _ => return Err(TokensJsonError::ObjectExpected),
    };
    if tokens.len() != params.len() {
        return Err(TokensJsonError::ParameterCountMismatch);
    }

    let mut result = Vec::with_capacity(tokens.len());
    for param in params {
        let value = tokens
            .remove(&param.name)
            .ok_or_else(|| TokensJsonError::ParameterNotFound(param.name.clone()))?;
        result.push(parse_abi_token(param, value)?);
    }

    Ok(result)
}

pub fn parse_abi_token(
    param: &ton_abi::Param,
    token: serde_json::Value,
) -> Result<ton_abi::Token, TokensJsonError> {
    let value = parse_abi_token_value(&param.kind, token)?;
    Ok(ton_abi::Token {
        name: param.name.clone(),
        value,
    })
}

pub fn parse_abi_token_value(
    param: &ton_abi::ParamType,
    value: serde_json::Value,
) -> Result<ton_abi::TokenValue, TokensJsonError> {
    let value = match param {
        &ton_abi::ParamType::Uint(size) | &ton_abi::ParamType::VarUint(size) => {
            let number = if let Some(value) = value.as_str() {
                let value = value.trim();
                if let Some(value) = value.strip_prefix("0x") {
                    BigUint::from_str_radix(value, 16)
                } else {
                    BigUint::from_str(value)
                }
                .map_err(|_| TokensJsonError::InvalidNumber(value.to_string()))
            } else if let Some(value) = value.as_f64() {
                // Check if there is a conversion error
                #[allow(clippy::float_cmp)]
                if value as u64 as f64 != value {
                    return Err(TokensJsonError::IntegerValueExpected(value));
                }

                if value >= 0.0 {
                    Ok(BigUint::from(value as u64))
                } else {
                    Err(TokensJsonError::UnsignedValueExpected(value))
                }
            } else {
                Err(TokensJsonError::NumberExpected)
            }?;

            match param {
                ton_abi::ParamType::Uint(_) => {
                    ton_abi::TokenValue::Uint(ton_abi::Uint { number, size })
                }
                _ => ton_abi::TokenValue::VarUint(size, number),
            }
        }
        &ton_abi::ParamType::Int(size) | &ton_abi::ParamType::VarInt(size) => {
            let number = if let Some(value) = value.as_str() {
                let value = value.trim();
                if let Some(value) = value.strip_prefix("0x") {
                    BigInt::from_str_radix(value, 16)
                } else {
                    BigInt::from_str(value)
                }
                .map_err(|_| TokensJsonError::InvalidNumber(value.to_string()))
            } else if let Some(value) = value.as_f64() {
                // Check if there is a conversion error
                #[allow(clippy::float_cmp)]
                if value as i64 as f64 != value {
                    return Err(TokensJsonError::IntegerValueExpected(value));
                }

                Ok(BigInt::from(value as i64))
            } else {
                Err(TokensJsonError::NumberExpected)
            }?;

            match param {
                ton_abi::ParamType::Int(_) => {
                    ton_abi::TokenValue::Int(ton_abi::Int { number, size })
                }
                _ => ton_abi::TokenValue::VarInt(size, number),
            }
        }
        ton_abi::ParamType::Bool => value
            .as_bool()
            .map(ton_abi::TokenValue::Bool)
            .ok_or(TokensJsonError::BoolExpected)?,
        ton_abi::ParamType::Tuple(params) => {
            let mut value = match value {
                serde_json::Value::Object(value) => value,
                _ => return Err(TokensJsonError::ObjectExpected),
            };
            if value.len() != params.len() {
                return Err(TokensJsonError::ParameterCountMismatch);
            }

            let mut result = Vec::with_capacity(params.len());
            for param in params {
                let value = value
                    .remove(&param.name)
                    .ok_or_else(|| TokensJsonError::ParameterNotFound(param.name.clone()))?;
                result.push(parse_abi_token(param, value)?);
            }

            ton_abi::TokenValue::Tuple(result)
        }
        ton_abi::ParamType::Array(param) => {
            let value = match value {
                serde_json::Value::Array(value) => value,
                _ => return Err(TokensJsonError::ArrayExpected),
            };

            ton_abi::TokenValue::Array(
                *param.clone(),
                value
                    .into_iter()
                    .map(|value| parse_abi_token_value(param.as_ref(), value))
                    .collect::<Result<_, _>>()?,
            )
        }
        ton_abi::ParamType::FixedArray(param, size) => {
            let value = match value {
                serde_json::Value::Array(value) => value,
                _ => return Err(TokensJsonError::ArrayExpected),
            };
            if value.len() != *size {
                return Err(TokensJsonError::InvalidArrayLength(value.len()));
            }

            ton_abi::TokenValue::FixedArray(
                *param.clone(),
                value
                    .into_iter()
                    .map(|value| parse_abi_token_value(param.as_ref(), value))
                    .collect::<Result<_, _>>()?,
            )
        }
        ton_abi::ParamType::Cell => {
            let value = if let Some(value) = value.as_str() {
                let value = value.trim();
                if value.is_empty() {
                    Ok(ton_types::Cell::default())
                } else {
                    base64::decode(&value)
                        .map_err(|_| TokensJsonError::InvalidCell)
                        .and_then(|value| {
                            ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(&value))
                                .map_err(|_| TokensJsonError::InvalidCell)
                        })
                }
            } else if value.is_null() {
                Ok(ton_types::Cell::default())
            } else {
                Err(TokensJsonError::StringExpected)
            }?;

            ton_abi::TokenValue::Cell(value)
        }
        ton_abi::ParamType::Map(param_key, param_value) => {
            let value = match value {
                serde_json::Value::Array(value) => value,
                _ => return Err(TokensJsonError::ArrayExpected),
            };

            let mut result = BTreeMap::new();

            for value in value.into_iter() {
                let mut value = match value {
                    serde_json::Value::Array(value) => value.into_iter(),
                    _ => return Err(TokensJsonError::MapItemExpected),
                };
                let (key, value) = match (value.next(), value.next()) {
                    (Some(key), Some(value)) => (key, value),
                    _ => return Err(TokensJsonError::MapItemExpected),
                };

                let key = parse_abi_token_value(param_key.as_ref(), key)?;
                let value = parse_abi_token_value(param_value.as_ref(), value)?;

                result.insert(key.to_string(), value);
            }

            ton_abi::TokenValue::Map(*param_key.clone(), *param_value.clone(), result)
        }
        ton_abi::ParamType::Address => {
            let value = if let Some(value) = value.as_str() {
                let value = value.trim();
                ton_block::MsgAddressInt::from_str(value)
                    .map_err(|_| TokensJsonError::InvalidAddress)
            } else {
                Err(TokensJsonError::StringExpected)
            }?;

            ton_abi::TokenValue::Address(match value {
                ton_block::MsgAddressInt::AddrStd(value) => ton_block::MsgAddress::AddrStd(value),
                ton_block::MsgAddressInt::AddrVar(value) => ton_block::MsgAddress::AddrVar(value),
            })
        }
        ton_abi::ParamType::Bytes => {
            let value = if let Some(value) = value.as_str() {
                let value = value.trim();
                if value.is_empty() {
                    Ok(Vec::new())
                } else {
                    base64::decode(value).map_err(|_| TokensJsonError::InvalidBytes)
                }
            } else {
                Err(TokensJsonError::StringExpected)
            }?;

            ton_abi::TokenValue::Bytes(value)
        }
        ton_abi::ParamType::String => {
            let value = match value {
                serde_json::Value::String(value) => value,
                _ => return Err(TokensJsonError::StringExpected),
            };
            ton_abi::TokenValue::String(value)
        }
        &ton_abi::ParamType::FixedBytes(size) => {
            let value = if let Some(value) = value.as_str() {
                let value = value.trim();
                base64::decode(&value).map_err(|_| TokensJsonError::InvalidBytes)
            } else {
                Err(TokensJsonError::StringExpected)
            }?;

            if value.len() != size {
                return Err(TokensJsonError::InvalidBytesLength(value.len()));
            }

            ton_abi::TokenValue::FixedBytes(value)
        }
        ton_abi::ParamType::Token => {
            let value = if let Some(value) = value.as_str() {
                let value = value.trim();
                if let Some(value) = value.strip_prefix("0x") {
                    u128::from_str_radix(value, 16)
                } else {
                    u128::from_str(value)
                }
                .map_err(|_| TokensJsonError::InvalidNumber(value.to_string()))
            } else if let Some(value) = value.as_f64() {
                if value >= 0.0 {
                    Ok(value as u128)
                } else {
                    Err(TokensJsonError::UnsignedValueExpected(value))
                }
            } else {
                Err(TokensJsonError::NumberExpected)
            }?;

            ton_abi::TokenValue::Token(ton_block::Grams(value))
        }
        ton_abi::ParamType::Time => {
            let value = if let Some(value) = value.as_str() {
                let value = value.trim();
                if let Some(value) = value.strip_prefix("0x") {
                    u64::from_str_radix(value, 16)
                } else {
                    u64::from_str(value)
                }
                .map_err(|_| TokensJsonError::InvalidNumber(value.to_string()))
            } else if let Some(value) = value.as_f64() {
                if value >= 0.0 {
                    Ok(value as u64)
                } else {
                    Err(TokensJsonError::UnsignedValueExpected(value))
                }
            } else {
                Err(TokensJsonError::NumberExpected)
            }?;

            ton_abi::TokenValue::Time(value)
        }
        ton_abi::ParamType::Expire => {
            let value = if let Some(value) = value.as_f64() {
                if value >= 0.0 {
                    Ok(value as u32)
                } else {
                    Err(TokensJsonError::UnsignedValueExpected(value))
                }
            } else if let Some(value) = value.as_str() {
                let value = value.trim();
                if let Some(value) = value.strip_prefix("0x") {
                    u32::from_str_radix(value, 16)
                } else {
                    u32::from_str(value)
                }
                .map_err(|_| TokensJsonError::InvalidNumber(value.to_string()))
            } else {
                Err(TokensJsonError::NumberExpected)
            }?;

            ton_abi::TokenValue::Expire(value)
        }
        ton_abi::ParamType::PublicKey => {
            let value = if let Some(value) = value.as_str() {
                let value = value.trim();
                if value.is_empty() {
                    Ok(None)
                } else {
                    hex::decode(value.strip_prefix("0x").unwrap_or(value))
                        .map_err(|_| TokensJsonError::InvalidPublicKey)
                        .and_then(|value| {
                            ed25519_dalek::PublicKey::from_bytes(&value)
                                .map_err(|_| TokensJsonError::InvalidPublicKey)
                        })
                        .map(Some)
                }
            } else {
                Err(TokensJsonError::StringExpected)
            }?;

            ton_abi::TokenValue::PublicKey(value)
        }
        ton_abi::ParamType::Optional(param) => match value {
            serde_json::Value::Null => ton_abi::TokenValue::Optional(*param.clone(), None),
            value => {
                let value = Box::new(parse_abi_token_value(param, value)?);
                ton_abi::TokenValue::Optional(*param.clone(), Some(value))
            }
        },
        ton_abi::ParamType::Ref(param) => {
            ton_abi::TokenValue::Ref(Box::new(parse_abi_token_value(param, value)?))
        }
    };

    Ok(value)
}

#[derive(thiserror::Error, Debug)]
pub enum TokensJsonError {
    #[error("Parameter count mismatch")]
    ParameterCountMismatch,
    #[error("Object expected")]
    ObjectExpected,
    #[error("Array expected")]
    ArrayExpected,
    #[error("Parameter not found: {}", .0)]
    ParameterNotFound(String),
    #[error("Invalid number: {}", .0)]
    InvalidNumber(String),
    #[error("Expected integer value: {}", .0)]
    IntegerValueExpected(f64),
    #[error("Expected unsigned value: {}", .0)]
    UnsignedValueExpected(f64),
    #[error("Expected integer as string or number")]
    NumberExpected,
    #[error("Expected boolean")]
    BoolExpected,
    #[error("Invalid array length: {}", .0)]
    InvalidArrayLength(usize),
    #[error("Invalid cell")]
    InvalidCell,
    #[error("Expected string")]
    StringExpected,
    #[error("Expected map item as array of key and value")]
    MapItemExpected,
    #[error("Invalid mapping key")]
    InvalidMappingKey,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Invalid bytes")]
    InvalidBytes,
    #[error("Invalid bytes length")]
    InvalidBytesLength(usize),
    #[error("Invalid public key")]
    InvalidPublicKey,
}
