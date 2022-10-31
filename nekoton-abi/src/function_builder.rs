use std::iter::FromIterator;

use ton_abi::contract::{AbiVersion, ABI_VERSION_2_0};
use ton_abi::{Function, Param, ParamType};

use super::{BuildTokenValue, TokenValueExt};

const ANSWER_ID: &str = "_answer_id";

#[derive(Debug, Clone)]
pub struct FunctionBuilder {
    /// Explicit function id
    id: Option<u32>,
    /// Contract function specification.
    /// ABI version
    abi_version: AbiVersion,
    /// Function name.
    name: String,
    /// Function header parameters.
    header: Vec<Param>,
    /// Function input.
    inputs: Vec<Param>,
    /// Function output.
    outputs: Vec<Param>,
    /// Whether answer_id is set
    responsible: bool,
}

impl FunctionBuilder {
    pub fn new(function_name: &str) -> Self {
        Self {
            id: None,
            abi_version: ABI_VERSION_2_0,
            name: function_name.to_string(),
            header: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            responsible: false,
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

    pub fn abi_version(mut self, abi_version: AbiVersion) -> Self {
        self.abi_version = abi_version;
        self
    }

    pub fn id(mut self, id: u32) -> Self {
        self.id = Some(id);
        self
    }

    /// Adds input param
    #[deprecated(note = "use `input` instead")]
    pub fn in_arg(self, name: &str, ty: ParamType) -> Self {
        self.input(name, ty)
    }

    /// Adds input param
    pub fn input(mut self, name: &str, ty: ParamType) -> Self {
        self.inputs.push(Param::new(name, ty));
        self
    }

    /// Sets the input params to the specified
    ///
    /// NOTE: Replaces previously added inputs
    pub fn inputs(mut self, inputs: Vec<Param>) -> Self {
        self.inputs = inputs;
        self
    }

    /// Adds output param
    #[deprecated(note = "use `output` instead")]
    pub fn out_arg(self, name: &str, ty: ton_abi::ParamType) -> Self {
        self.output(name, ty)
    }

    /// Adds output param
    pub fn output(mut self, name: &str, ty: ton_abi::ParamType) -> Self {
        self.outputs.push(Param::new(name, ty));
        self
    }

    /// Sets the output params to the specified
    ///
    /// NOTE: Replaces previously added outputs
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
        match self.id {
            Some(id) => {
                fun.input_id = id;
                fun.output_id = id;
            }
            None => {
                let id = fun.get_function_id();
                fun.input_id = id & 0x7FFFFFFF;
                fun.output_id = id | 0x80000000;
            }
        }
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

    #[deprecated(note = "use `item` instead")]
    pub fn arg(self, name: &str, ty: ParamType) -> Self {
        self.item(name, ty)
    }

    pub fn item(mut self, name: &str, ty: ParamType) -> Self {
        self.types.push(Param::new(name, ty));
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
        let original = nekoton_contracts::old_tip3::token_wallet_contract::transfer();

        let imposter = FunctionBuilder::new("transfer")
            .input("to", ParamType::Address)
            .input("tokens", ParamType::Uint(128))
            .input("grams", ParamType::Uint(128))
            .input("send_gas_to", ParamType::Address)
            .input("notify_receiver", ParamType::Bool)
            .input("payload", ParamType::Cell)
            .build();

        assert_eq!(original, &imposter)
    }
}
