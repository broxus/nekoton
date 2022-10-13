use quote::quote;

use crate::ast::*;
use crate::parsing_context::*;
use crate::utils::*;

pub fn impl_derive_known_param_type(
    input: syn::DeriveInput,
    plain: bool,
) -> Result<proc_macro2::TokenStream, Vec<syn::Error>> {
    let cx = ParsingContext::new();
    let container = match Container::from_ast(&cx, &input) {
        Some(container) => container,
        None => return Err(cx.check().unwrap_err()),
    };

    if plain && matches!(&container.data, Data::Enum(_)) {
        cx.error_spanned_by(&input.ident, "Plain packer is not supported for enums");
    }

    cx.check()?;

    let ident = &container.ident;
    let result = match &container.data {
        Data::Enum(_) => {
            let body = if container.attrs.enum_bool {
                quote! { ::ton_abi::ParamType::Bool }
            } else {
                quote! { ::ton_abi::ParamType::Uint(8) }
            };

            quote! {
                impl ::nekoton_abi::KnownParamType for #ident {
                    fn param_type() -> ::ton_abi::ParamType {
                        #body
                    }
                }
            }
        }
        Data::Struct(_, fields) => {
            if plain {
                let body = serialize_struct(&container, fields, StructType::Plain);
                quote! {
                    impl ::nekoton_abi::KnownParamTypePlain for #ident {
                        fn param_type() -> Vec<::ton_abi::Param> {
                            #body
                        }
                    }
                }
            } else {
                let body = serialize_struct(&container, fields, StructType::Tuple);
                quote! {
                    impl ::nekoton_abi::KnownParamType for #ident {
                        fn param_type() -> ::ton_abi::ParamType {
                            #body
                        }
                    }
                }
            }
        }
    };
    Ok(result)
}

fn serialize_struct(
    _container: &Container<'_>,
    fields: &[Field<'_>],
    struct_type: StructType,
) -> proc_macro2::TokenStream {
    let field_count = fields.len();

    let definition = quote! {
        let mut params: Vec<::ton_abi::Param> = Vec::with_capacity(#field_count);
    };

    let build_fields = fields.iter().map(|f| {
        if f.attrs.skip {
            return quote! {}; // do nothing
        }

        let name = f.original.ident.as_ref().unwrap();
        let field_name = match &f.attrs.name {
            Some(v) => v.clone(),
            None => name.to_string(),
        };

        let ty = &f.original.ty;

        if let Some(type_name) = f.attrs.type_name.as_ref() {
            let param_type = type_name.get_param_type();
            match f.attrs.is_array {
                true => {
                    quote! {
                        params.push(::ton_abi::Param::new(
                            #field_name,
                            ::ton_abi::ParamType::Array(Box::new(#param_type))
                        ))
                    }
                }
                false => {
                    quote! {
                        params.push(::ton_abi::Param::new(#field_name, #param_type))
                    }
                }
            }
        } else if let Some(with) = f.attrs.with.as_ref() {
            quote! {
                params.push(::ton_abi::Param::new(#field_name, #with::param_type()))
            }
        } else if let Some(param_type_with) = f.attrs.param_type_with.as_ref() {
            quote! {
                params.push(::ton_abi::Param::new(#field_name, #param_type_with()))
            }
        } else {
            match f.attrs.is_array {
                true => {
                    quote! {
                        params.push(::ton_abi::Param::new(
                            #field_name,
                            ::ton_abi::ParamType::Array(Box::new(<#ty as ::nekoton_abi::KnownParamTypeArray<_>>::item_param_type())),
                        ))
                    }
                }
                false => {
                    quote! {
                        params.push(::ton_abi::Param::new(
                            #field_name,
                            <#ty as ::nekoton_abi::KnownParamType>::param_type(),
                        ))
                    }
                }
            }
        }
    });

    match struct_type {
        StructType::Plain => {
            quote! {
                #definition
                #(#build_fields;)*
                params
            }
        }
        StructType::Tuple => {
            quote! {
                #definition
                #(#build_fields;)*
                ::ton_abi::ParamType::Tuple(params)
            }
        }
    }
}
