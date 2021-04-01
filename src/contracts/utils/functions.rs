use super::{Function, StandaloneToken};
use tiny_hderive::bip44::IntoDerivationPath;
use ton_abi::{Param, ParamType};

#[derive(Default)]
pub struct FunctionBuilder {
    /// Contract function specification.
    /// ABI version
    pub abi_version: u8,
    /// Function name.
    pub name: String,
    /// Function header parameters.
    pub header: Vec<Param>,
    /// Function input.
    pub inputs: Vec<Param>,
    /// Function output.
    pub outputs: Vec<Param>,
    /// Function ID for inbound messages
    pub input_id: u32,
    /// Function ID for outbound messages
    pub output_id: u32,
}

impl FunctionBuilder {
    pub fn new(function_name: &str) -> Self {
        Self {
            name: function_name.to_string(),
            abi_version: 2,
            ..Default::default()
        }
    }

    pub fn in_arg(mut self, name: &str, arg_type: ParamType) -> Self {
        self.inputs.push(Param::new(name, arg_type));
        self
    }

    pub fn out_arg(mut self, name: &str, arg_type: ParamType) -> Self {
        self.outputs.push(Param::new(name, arg_type));
        self
    }

    pub fn header(mut self, name: &str, arg_type: ParamType) -> Self {
        self.header.push(Param::new(name, arg_type));
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
