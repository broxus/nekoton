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
    clippy::dbg_macro,
    unexpected_cfgs
)]

use quote::quote;
use syn::parse_macro_input;

use self::known_param_type::*;
use self::pack_abi::*;
use self::unpack_abi::*;

mod ast;
mod attr;
mod known_param_type;
mod pack_abi;
mod parsing_context;
mod symbol;
mod unpack_abi;
mod utils;

#[proc_macro_derive(KnownParamType, attributes(abi))]
pub fn derive_known_param_type(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    impl_derive_known_param_type(input, false)
        .unwrap_or_else(to_compile_errors)
        .into()
}

#[proc_macro_derive(KnownParamTypePlain, attributes(abi))]
pub fn derive_known_param_type_plain(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    impl_derive_known_param_type(input, true)
        .unwrap_or_else(to_compile_errors)
        .into()
}

#[proc_macro_derive(PackAbi, attributes(abi))]
pub fn derive_pack_abi(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    impl_derive_pack_abi(input, false)
        .unwrap_or_else(to_compile_errors)
        .into()
}

#[proc_macro_derive(PackAbiPlain, attributes(abi))]
pub fn derive_pack_abi_plain(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    impl_derive_pack_abi(input, true)
        .unwrap_or_else(to_compile_errors)
        .into()
}

#[proc_macro_derive(UnpackAbi, attributes(abi))]
pub fn derive_unpack_abi(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    impl_derive_unpack_abi(input, false)
        .unwrap_or_else(to_compile_errors)
        .into()
}

#[proc_macro_derive(UnpackAbiPlain, attributes(abi))]
pub fn derive_unpack_abi_plain(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);
    impl_derive_unpack_abi(input, true)
        .unwrap_or_else(to_compile_errors)
        .into()
}

fn to_compile_errors(errors: Vec<syn::Error>) -> proc_macro2::TokenStream {
    let compile_errors = errors.iter().map(syn::Error::to_compile_error);
    quote!(#(#compile_errors)*)
}
