use ton_abi::{Function, Param, ParamType};

use super::{BuildTokenValue, TokenValueExt};
use std::iter::FromIterator;

const ANSWER_ID: &str = "_answer_id";

#[derive(Default, Debug, Clone)]
pub struct FunctionBuilder {
    /// Contract function specification.
    /// ABI version
    abi_version: u8,
    /// Function name.
    name: String,
    /// Function header parameters.
    header: Vec<Param>,
    /// Function input.
    inputs: Vec<Param>,
    /// Function output.
    outputs: Vec<Param>,
    /// Function ID for inbound messages
    input_id: u32,
    /// Function ID for outbound messages
    output_id: u32,
    /// Whether answer_id is set
    responsible: bool,
}

impl FunctionBuilder {
    pub fn new(function_name: &str) -> Self {
        Self {
            name: function_name.to_string(),
            abi_version: 2,
            ..Default::default()
        }
    }

    pub fn new_responsible(function_name: &str) -> Self {
        let mut function = Self::new(function_name);
        function.make_responsible();
        function
    }

    pub fn default_headers(self) -> Self {
        self.pubkey_header().time_header().expire_header()
    }

    pub fn pubkey_header(self) -> Self {
        self.header("pubkey", ParamType::PublicKey)
    }

    pub fn time_header(self) -> Self {
        self.header("time", ParamType::Time)
    }

    pub fn expire_header(self) -> Self {
        self.header("expire", ParamType::Expire)
    }

    pub fn make_responsible(&mut self) {
        if self.inputs.is_empty() {
            self.inputs.push(Param::new(ANSWER_ID, ParamType::Uint(32)));
        } else if !self.responsible {
            self.inputs
                .insert(0, Param::new(ANSWER_ID, ParamType::Uint(32)));
        }
        self.responsible = true;
    }

    pub fn in_arg(mut self, name: &str, arg_type: ParamType) -> Self {
        self.inputs.push(Param::new(name, arg_type));
        self
    }

    pub fn inputs(mut self, inputs: Vec<Param>) -> Self {
        self.inputs = inputs;
        self
    }

    pub fn out_arg(mut self, name: &str, arg_type: ton_abi::ParamType) -> Self {
        self.outputs.push(Param::new(name, arg_type));
        self
    }

    pub fn outputs(mut self, outputs: Vec<Param>) -> Self {
        self.outputs = outputs;
        self
    }

    pub fn header(mut self, name: &str, arg_type: ton_abi::ParamType) -> Self {
        self.header.push(Param::new(name, arg_type));
        self
    }

    pub fn headers(mut self, headers: Vec<Param>) -> Self {
        self.header = headers;
        self
    }

    pub fn build(self) -> Function {
        let mut fun = Function {
            abi_version: self.abi_version,
            name: self.name,
            header: self.header,
            inputs: self.inputs,
            outputs: self.outputs,
            input_id: 0,
            output_id: 0,
        };
        let id = fun.get_function_id();
        fun.input_id = id & 0x7FFFFFFF;
        fun.output_id = id | 0x80000000;
        fun
    }
}

#[derive(Default, Debug, Clone)]
pub struct TupleBuilder {
    types: Vec<Param>,
}

impl TupleBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn arg(mut self, name: &str, arg_type: ParamType) -> Self {
        self.types.push(Param::new(name, arg_type));
        self
    }

    pub fn build(self) -> ParamType {
        ParamType::Tuple(self.types)
    }
}

impl FromIterator<Param> for TupleBuilder {
    fn from_iter<T: IntoIterator<Item = Param>>(iter: T) -> Self {
        Self {
            types: iter.into_iter().collect(),
        }
    }
}

pub fn answer_id() -> ton_abi::Token {
    0u32.token_value().named(ANSWER_ID)
}

#[cfg(test)]
mod tests {
    use ton_abi::ParamType;

    use super::*;

    #[test]
    fn build() {
        let original = nekoton_contracts::abi::ton_token_wallet_v3()
            .function("transfer")
            .unwrap();
        let imposter = FunctionBuilder::new("transfer")
            .default_headers()
            .in_arg("to", ParamType::Address)
            .in_arg("tokens", ParamType::Uint(128))
            .in_arg("grams", ParamType::Uint(128))
            .in_arg("send_gas_to", ParamType::Address)
            .in_arg("notify_receiver", ParamType::Bool)
            .in_arg("payload", ParamType::Cell)
            .build();

        assert_eq!(original, &imposter)
    }
}
