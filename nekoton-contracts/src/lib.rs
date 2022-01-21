pub mod abi;
pub mod code;

pub mod tip3;
pub mod tip4;

mod utils {
    macro_rules! declare_function {
        (name: $name:literal, inputs: $inputs:expr, outputs: $outputs:expr $(,)?) => {
            static ABI: once_cell::race::OnceBox<ton_abi::Function> =
                once_cell::race::OnceBox::new();
            ABI.get_or_init(|| {
                let mut function = ton_abi::Function {
                    abi_version: ton_abi::contract::ABI_VERSION_2_2,
                    name: ($name).to_string(),
                    header: Vec::new(),
                    inputs: $inputs,
                    outputs: $outputs,
                    input_id: 0,
                    output_id: 0,
                };
                let id = function.get_function_id();
                function.input_id = id & 0x7FFFFFFF;
                function.output_id = id | 0x80000000;
                Box::new(function)
            })
        };
    }

    pub(crate) use declare_function;
}
