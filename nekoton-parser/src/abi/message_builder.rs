use anyhow::Result;
use num_bigint::BigUint;
use ton_abi::{Contract, Function, Token, TokenValue};

use nekoton_token_packer::{BuildTokenValue, BuildTokenValues};

#[derive(Debug)]
pub struct MessageBuilder<'a> {
    function: &'a Function,
    inputs: Vec<Token>,
}

impl<'a> MessageBuilder<'a> {
    pub fn new(contract: &'a Contract, function_name: &str) -> Result<Self> {
        let function = contract
            .function(function_name)
            .map_err(|_| BuilderError::InvalidAbi)?;
        let input = Vec::with_capacity(function.inputs.len());

        Ok(Self {
            function,
            inputs: input,
        })
    }

    pub fn arg<A>(mut self, value: A) -> Self
    where
        A: BuildTokenValue,
    {
        let name = &self.function.inputs[self.inputs.len()].name;
        self.inputs.push(Token::new(name, value.token_value()));
        self
    }

    pub fn args<A>(mut self, values: A) -> Self
    where
        A: BuildTokenValues,
    {
        let token_values = values.token_values();
        let args_from = self.inputs.len();
        let args_to = args_from + token_values.len();

        let inputs = &self.function.inputs;
        self.inputs.extend(
            (args_from..args_to)
                .into_iter()
                .map(|i| inputs[i].name.as_ref())
                .zip(token_values.into_iter())
                .map(|(name, value)| Token::new(name, value)),
        );
        self
    }

    pub fn build(self) -> (&'a Function, Vec<Token>) {
        (self.function, self.inputs)
    }
}

#[derive(Debug)]
pub struct BigUint256(pub BigUint);

impl BuildTokenValue for BigUint256 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: self.0,
            size: 256,
        })
    }
}

#[derive(Debug)]
pub struct BigUint128(pub BigUint);

impl BuildTokenValue for BigUint128 {
    fn token_value(self) -> TokenValue {
        TokenValue::Uint(ton_abi::Uint {
            number: self.0,
            size: 128,
        })
    }
}

#[derive(thiserror::Error, Debug)]
enum BuilderError {
    #[error("Invalid ABI")]
    InvalidAbi,
}
