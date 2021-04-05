use ton_abi::{Function, Param, ParamType};

#[allow(dead_code)]
#[derive(Default)]
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
}

impl FunctionBuilder {
    pub fn new(function_name: &str) -> Self {
        Self {
            name: function_name.to_string(),
            abi_version: 2,
            ..Default::default()
        }
    }

    pub fn default_headers(self) -> Self {
        self.header("pubkey", ParamType::PublicKey)
            .header("time", ParamType::Time)
            .header("expire", ParamType::Expire)
    }

    pub fn in_arg(mut self, name: &str, arg_type: ParamType) -> Self {
        self.inputs.push(Param::new(name, arg_type));
        self
    }

    pub fn out_arg(mut self, name: &str, arg_type: ton_abi::ParamType) -> Self {
        self.outputs.push(Param::new(name, arg_type));
        self
    }

    pub fn header(mut self, name: &str, arg_type: ton_abi::ParamType) -> Self {
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

#[cfg(test)]
mod test {
    use crate::helpers::abi::FunctionBuilder;
    use ton_abi::ParamType;

    // "name": "transfer",
    // "inputs": [
    // {"name":"to","type":"address"},
    // {"name":"tokens","type":"uint128"},
    // {"name":"grams","type":"uint128"},
    // {"name":"send_gas_to","type":"address"},
    // {"name":"notify_receiver","type":"bool"},
    //     {"name":"payload","type":"cell"}
    //     ],
    //     "outputs": [
    //     ]
    #[test]
    fn build() {
        let original = crate::contracts::abi::ton_token_wallet()
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
