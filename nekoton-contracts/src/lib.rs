pub mod abi;
pub mod code;

pub mod tip3;
pub mod tip3_1;
pub mod tip6;
pub mod wallets;

mod utils {
    macro_rules! declare_function {
        (
            $(abi: $abi:expr,)?
            $(function_id: $id:literal,)?
            name: $name:literal,
            inputs: $inputs:expr,
            outputs: $outputs:expr$(,)?
        ) => {
            static ABI: once_cell::race::OnceBox<ton_abi::Function> =
                once_cell::race::OnceBox::new();
            ABI.get_or_init(|| {
                let mut function = ton_abi::Function {
                    abi_version: $crate::utils::declare_function!(@abi_version $($abi)?),
                    name: ($name).to_string(),
                    header: Vec::new(),
                    inputs: $inputs,
                    outputs: $outputs,
                    input_id: 0,
                    output_id: 0,
                };
                let id = $crate::utils::declare_function!(@function_id function $($id)?);
                function.input_id = id & 0x7FFFFFFF;
                function.output_id = id | 0x80000000;
                Box::new(function)
            })
        };

        (@abi_version) => { ::ton_abi::contract::ABI_VERSION_2_2 };
        (@abi_version $abi:expr) => { $abi:expr };

        (@function_id $f:ident) => { $f.get_function_id() };
        (@function_id $f:ident $id:literal) => { $id };
    }

    pub(crate) use declare_function;
}
