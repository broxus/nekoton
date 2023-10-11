#![warn(
    missing_copy_implementations,
    macro_use_extern_crate,
    keyword_idents,
    explicit_outlives_requirements,
    meta_variable_misuse,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    clippy::await_holding_lock,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::doc_markdown,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::exit,
    clippy::explicit_into_iter_loop,
    clippy::filter_map_next,
    clippy::fn_params_excessive_bools,
    clippy::if_let_mutex,
    clippy::imprecise_flops,
    clippy::inefficient_to_string,
    clippy::let_unit_value,
    clippy::linkedlist,
    clippy::lossy_float_literal,
    clippy::macro_use_imports,
    clippy::map_flatten,
    clippy::map_unwrap_or,
    clippy::match_on_vec_items,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::mem_forget,
    clippy::mismatched_target_os,
    clippy::needless_borrow,
    clippy::needless_continue,
    clippy::option_option,
    clippy::ref_option_ref,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::string_add_assign,
    clippy::string_add,
    clippy::string_to_string,
    clippy::suboptimal_flops,
    clippy::todo,
    clippy::unimplemented,
    clippy::unnested_or_patterns,
    clippy::unused_self,
    clippy::verbose_file_reads,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    clippy::print_stdout,
    clippy::dbg_macro
)]

use anyhow::Result;
use nekoton_abi::{ExecutionContext, ExecutionOutput};

pub mod dens;
pub mod old_tip3;
pub mod tip1155;
pub mod tip3;
pub mod tip3_1;
pub mod tip4_1;
pub mod tip4_2;
pub mod tip4_3;
pub mod tip6;
pub mod wallets;

trait RunLocalSimple {
    fn run_local_simple(
        &self,
        function: &ton_abi::Function,
        inputs: &[ton_abi::Token],
    ) -> Result<Vec<ton_abi::Token>>;

    fn run_local_responsible_simple(
        &self,
        function: &ton_abi::Function,
        inputs: &[ton_abi::Token],
    ) -> Result<Vec<ton_abi::Token>>;
}

impl RunLocalSimple for ExecutionContext<'_> {
    fn run_local_simple(
        &self,
        function: &ton_abi::Function,
        inputs: &[ton_abi::Token],
    ) -> Result<Vec<ton_abi::Token>> {
        let ExecutionOutput {
            tokens,
            result_code,
        } = self.run_local(function, inputs)?;
        tokens.ok_or_else(|| NonZeroResultCode(result_code).into())
    }

    fn run_local_responsible_simple(
        &self,
        function: &ton_abi::Function,
        inputs: &[ton_abi::Token],
    ) -> Result<Vec<ton_abi::Token>> {
        let ExecutionOutput {
            tokens,
            result_code,
        } = self.run_local_responsible(function, inputs)?;
        tokens.ok_or_else(|| NonZeroResultCode(result_code).into())
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
#[error("Non zero result code: {0}")]
pub struct NonZeroResultCode(pub i32);

mod utils {
    macro_rules! declare_function {
        (
            $(abi: $abi:ident,)?
            $(function_id: $id:literal,)?
            $(header: [$($header:ident),+],)?
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
                    header: $crate::utils::declare_function!(@header $($($header),+)?),
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
        (@abi_version v2_0) => { ::ton_abi::contract::ABI_VERSION_2_0 };
        (@abi_version v2_1) => { ::ton_abi::contract::ABI_VERSION_2_1 };
        (@abi_version v2_2) => { ::ton_abi::contract::ABI_VERSION_2_2 };
        (@abi_version v2_3) => { ::ton_abi::contract::ABI_VERSION_2_3 };

        (@function_id $f:ident) => { $f.get_function_id() };
        (@function_id $f:ident $id:literal) => { $id };

        (@header) => { Vec::new() };
        (@header $($header:ident),+) => {
            vec![$($crate::utils::declare_function!(@header_item $header)),+]
        };
        (@header_item pubkey) => {
            ::ton_abi::Param::new("pubkey", ::ton_abi::ParamType::PublicKey)
        };
        (@header_item time) => {
            ::ton_abi::Param::new("time", ::ton_abi::ParamType::Time)
        };
        (@header_item expire) => {
            ::ton_abi::Param::new("expire", ::ton_abi::ParamType::Expire)
        };
    }

    pub(crate) use declare_function;
}
