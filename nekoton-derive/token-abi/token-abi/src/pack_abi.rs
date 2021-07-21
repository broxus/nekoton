use proc_macro2::Ident;
use quote::quote;

use crate::ast::*;
use crate::attr::TypeName;
use crate::parsing_context::*;
use crate::utils::*;

pub fn impl_derive_pack_abi(
    input: syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, Vec<syn::Error>> {
    let cx = ParsingContext::new();
    let container = match Container::from_ast(&cx, &input) {
        Some(container) => container,
        None => return Err(cx.check().unwrap_err()),
    };
    cx.check()?;

    let ident = &container.ident;
    let result = match &container.data {
        Data::Enum(variants) => {
            let body = serialize_enum(&container, variants);
            quote! {
                impl nekoton_token_packer::BuildTokenValue for #ident {
                    fn token_value(self) -> ton_abi::TokenValue {
                        #body
                    }
                }

                impl nekoton_token_packer::StandaloneToken for #ident {}
            }
        }
        Data::Struct(_, fields) => {
            if container.attrs.plain {
                let body = serialize_struct(&container, fields, StructType::Plain);
                quote! {
                    impl nekoton_token_packer::PackTokens for #ident {
                        fn pack(self) -> Vec<ton_abi::Token> {
                            #body
                        }
                    }
                }
            } else {
                let body = serialize_struct(&container, fields, StructType::Tuple);
                quote! {
                    impl nekoton_token_packer::BuildTokenValue for #ident {
                        fn token_value(self) -> ton_abi::TokenValue {
                            #body
                        }
                    }
                }
            }
        }
    };
    Ok(result)
}

enum StructType {
    Tuple,
    Plain,
}

fn serialize_enum(container: &Container, variants: &[Variant]) -> proc_macro2::TokenStream {
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

            quote! {
                #name::#ident => #number.token_value()
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
        let mut tokens: Vec<ton_abi::Token> = Vec::new();
    };

    let build_fields = fields.iter().map(|f| {
        if is_abi(&f.original.attrs) {
            let name = f.original.ident.as_ref().unwrap();
            let field_name = match &f.attrs.name {
                Some(v) => v.clone(),
                None => name.to_string(),
            };

            match &f.attrs.pack_with {
                Some(data) => {
                    quote! {
                        tokens.push(#data(#field_name, self.#name))
                    }
                }
                None => match &f.attrs.type_name {
                    Some(type_name) => {
                        let handler = get_handler(type_name, name);
                        quote! {
                            tokens.push(ton_abi::Token::new(#field_name, #handler))
                        }
                    }
                    None => {
                        quote! {
                            tokens.push(ton_abi::Token::new(#field_name, self.#name.token_value()))
                        }
                    }
                },
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
                return ton_abi::TokenValue::Tuple(tokens);
            }
        }
    }
}

fn get_handler(type_name: &TypeName, name: &Ident) -> proc_macro2::TokenStream {
    match type_name {
        TypeName::Int8 => {
            quote! {
                ton_abi::TokenValue::Int(ton_abi::Int { number: nekoton_token_packer::num_bigint::BigInt::from(self.#name), size: 8 })
            }
        }
        TypeName::Uint8 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: nekoton_token_packer::num_bigint::BigUint::from(self.#name), size: 8 })
            }
        }
        TypeName::Uint16 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: nekoton_token_packer::num_bigint::BigUint::from(self.#name), size: 16 })
            }
        }
        TypeName::Uint32 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: nekoton_token_packer::num_bigint::BigUint::from(self.#name), size: 32 })
            }
        }
        TypeName::Uint64 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: nekoton_token_packer::num_bigint::BigUint::from(self.#name), size: 64 })
            }
        }
        TypeName::Uint128 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: nekoton_token_packer::num_bigint::BigUint::from(self.#name), size: 128 })
            }
        }
        TypeName::Uint160 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: nekoton_token_packer::num_bigint::BigUint::from_bytes_be(self.#name.as_slice()), size: 160 })
            }
        }
        TypeName::Uint256 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: nekoton_token_packer::num_bigint::BigUint::from_bytes_be(self.#name.as_slice()), size: 256 })
            }
        }
        TypeName::Address => {
            quote! {
                ton_abi::TokenValue::Address(match self.#name {
                    ton_block::MsgAddressInt::AddrStd(addr) => ton_block::MsgAddress::AddrStd(addr),
                    ton_block::MsgAddressInt::AddrVar(addr) => ton_block::MsgAddress::AddrVar(addr),
                })
            }
        }
        TypeName::Cell => {
            quote! {
                ton_abi::TokenValue::Cell(self.#name)
            }
        }
        TypeName::Bool => {
            quote! {
                ton_abi::TokenValue::Bool(self.#name)
            }
        }
        TypeName::Biguint128 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: nekoton_token_packer::num_bigint::BigUint::from_bytes_be(self.#name.as_slice()), size: 128 })
            }
        }
        TypeName::None => unreachable!(),
    }
}
