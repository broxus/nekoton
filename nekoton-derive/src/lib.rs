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
