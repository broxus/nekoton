use proc_macro2::Ident;
use quote::quote;

use crate::ast::*;
use crate::attr::TypeName;
use crate::parsing_context::*;
use crate::utils::*;

pub fn impl_derive_pack_abi(
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
        Data::Enum(variants) => {
            let enum_type = if container.attrs.enum_bool {
                EnumType::Bool
            } else {
                EnumType::Int
            };
            let body = serialize_enum(&container, variants, enum_type);
            quote! {
                impl ::nekoton_abi::BuildTokenValue for #ident {
                    fn token_value(self) -> ::ton_abi::TokenValue {
                        #body
                    }
                }

                impl ::nekoton_abi::PackAbi for #ident {
                    fn pack(self) -> ::ton_abi::TokenValue {
                        ::nekoton_abi::BuildTokenValue::token_value(self)
                    }
                }
            }
        }
        Data::Struct(_, fields) => {
            if plain {
                let body = serialize_struct(&container, fields, StructType::Plain);
                quote! {
                    impl ::nekoton_abi::PackAbiPlain for #ident {
                        fn pack(self) -> Vec<::ton_abi::Token> {
                            #body
                        }
                    }
                }
            } else {
                let body = serialize_struct(&container, fields, StructType::Tuple);
                quote! {
                    impl ::nekoton_abi::BuildTokenValue for #ident {
                        fn token_value(self) -> ::ton_abi::TokenValue {
                            #body
                        }
                    }

                    impl ::nekoton_abi::PackAbi for #ident {
                        fn pack(self) -> ::ton_abi::TokenValue {
                            ::nekoton_abi::BuildTokenValue::token_value(self)
                        }
                    }
                }
            }
        }
    };
    Ok(result)
}

fn serialize_enum(
    container: &Container,
    variants: &[Variant],
    enum_type: EnumType,
) -> proc_macro2::TokenStream {
    let name = &container.ident;

    let build_variants = variants
        .iter()
        .filter_map(|variant| {
            variant
                .original
                .discriminant
                .as_ref()
                .map(|(_, discriminant)| (variant.ident.clone(), discriminant))
        })
        .map(|(ident, discriminant)| {
            let token = quote::ToTokens::to_token_stream(discriminant).to_string();
            let number = token.parse::<u8>().unwrap();

            match enum_type {
                EnumType::Int => quote! {
                    #name::#ident => ::nekoton_abi::BuildTokenValue::token_value(#number)
                },
                EnumType::Bool => match number {
                    0 => quote! {
                        #name::#ident => ::nekoton_abi::BuildTokenValue::token_value(false)
                    },
                    _ => quote! {
                        #name::#ident => ::nekoton_abi::BuildTokenValue::token_value(true)
                    },
                },
            }
        });

    quote! {
        match self {
            #(#build_variants,)*
        }
    }
}

fn serialize_struct(
    _container: &Container,
    fields: &[Field],
    struct_type: StructType,
) -> proc_macro2::TokenStream {
    let definition = quote! {
        let mut tokens: Vec<::ton_abi::Token> = Vec::new();
    };

    let build_fields = fields.iter().map(|f| {
        if is_abi(&f.original.attrs) {
            let name = f.original.ident.as_ref().unwrap();
            let field_name = match &f.attrs.name {
                Some(v) => v.clone(),
                None => name.to_string(),
            };

            if let Some(type_name) = f.attrs.type_name.as_ref() {
                let handler = get_handler(type_name, name);
                quote! {
                    tokens.push(::ton_abi::Token::new(#field_name, #handler))
                }
            } else if let Some(with) = f.attrs.with.as_ref() {
                quote! {
                    tokens.push(::ton_abi::Token::new(#field_name, #with::pack(self.#name)))
                }
            } else if let Some(pack_with) = f.attrs.pack_with.as_ref() {
                quote! {
                    tokens.push(::ton_abi::Token::new(#field_name, #pack_with(self.#name)))
                }
            } else {
                quote! {
                    tokens.push(::nekoton_abi::TokenValueExt::named(
                        ::nekoton_abi::BuildTokenValue::token_value(self.#name),
                        #field_name
                    ))
                }
            }
        } else {
            quote! {} // do nothing
        }
    });

    match struct_type {
        StructType::Plain => {
            quote! {
                #definition
                #(#build_fields;)*
                return tokens;
            }
        }
        StructType::Tuple => {
            quote! {
                #definition
                #(#build_fields;)*
                return ::ton_abi::TokenValue::Tuple(tokens);
            }
        }
    }
}

fn get_handler(type_name: &TypeName, name: &Ident) -> proc_macro2::TokenStream {
    match type_name {
        TypeName::Int8 => {
            quote! {
                ::ton_abi::TokenValue::Int(::ton_abi::Int { number: ::nekoton_abi::num_bigint::BigInt::from(self.#name), size: 8 })
            }
        }
        TypeName::Uint8 => {
            quote! {
                ::ton_abi::TokenValue::Uint(::ton_abi::Uint { number: ::nekoton_abi::num_bigint::BigUint::from(self.#name), size: 8 })
            }
        }
        TypeName::Uint16 => {
            quote! {
                ::ton_abi::TokenValue::Uint(::ton_abi::Uint { number: ::nekoton_abi::num_bigint::BigUint::from(self.#name), size: 16 })
            }
        }
        TypeName::Uint32 => {
            quote! {
                ::ton_abi::TokenValue::Uint(::ton_abi::Uint { number: ::nekoton_abi::num_bigint::BigUint::from(self.#name), size: 32 })
            }
        }
        TypeName::Uint64 => {
            quote! {
                ::ton_abi::TokenValue::Uint(::ton_abi::Uint { number: ::nekoton_abi::num_bigint::BigUint::from(self.#name), size: 64 })
            }
        }
        TypeName::Uint128 => {
            quote! {
                ::ton_abi::TokenValue::Uint(::ton_abi::Uint { number: ::nekoton_abi::num_bigint::BigUint::from(self.#name), size: 128 })
            }
        }
        TypeName::Address => {
            quote! {
                ::ton_abi::TokenValue::Address(match self.#name {
                    ::ton_block::MsgAddressInt::AddrStd(addr) => ::ton_block::MsgAddress::AddrStd(addr),
                    ::ton_block::MsgAddressInt::AddrVar(addr) => ::ton_block::MsgAddress::AddrVar(addr),
                })
            }
        }
        TypeName::Cell => {
            quote! {
                ::ton_abi::TokenValue::Cell(self.#name)
            }
        }
        TypeName::Bool => {
            quote! {
                ::ton_abi::TokenValue::Bool(self.#name)
            }
        }
        TypeName::String => {
            quote! {
                ::ton_abi::TokenValue::Bytes(self.#name.as_bytes().into())
            }
        }
        TypeName::Bytes => {
            quote! {
                ::ton_abi::TokenValue::Bytes(self.#name)
            }
        }
        TypeName::None => unreachable!(),
    }
}
