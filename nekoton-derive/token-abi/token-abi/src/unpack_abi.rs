use quote::quote;

use crate::ast::*;
use crate::attr::TypeName;
use crate::parsing_context::*;
use crate::utils::*;

pub fn impl_derive_unpack_abi(
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
                impl nekoton_token_unpacker::UnpackToken<#ident> for ton_abi::TokenValue {
                    fn unpack(self) -> nekoton_token_unpacker::ContractResult<#ident> {
                        #body
                    }
                }

                impl nekoton_token_unpacker::StandaloneToken for #ident {}
            }
        }
        Data::Struct(_, fields) => {
            if container.attrs.plain {
                let body = serialize_struct(&container, fields, StructType::Plain);
                quote! {
                    impl nekoton_token_unpacker::UnpackToken<#ident> for Vec<ton_abi::Token> {
                        fn unpack(self) -> nekoton_token_unpacker::ContractResult<#ident> {
                            #body
                        }
                    }
                }
            } else {
                let body = serialize_struct(&container, fields, StructType::Tuple);
                quote! {
                    impl nekoton_token_unpacker::UnpackToken<#ident> for ton_abi::TokenValue {
                        fn unpack(self) -> nekoton_token_unpacker::ContractResult<#ident> {
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
                Some(#number) => Ok(#name::#ident)
            }
        });

    quote! {
        match self {
            ton_abi::TokenValue::Uint(int) => match nekoton_token_unpacker::num_traits::ToPrimitive::to_u8(&int.number) {
                #(#build_variants,)*
                _ => Err(nekoton_token_unpacker::UnpackerError::InvalidAbi),
            },
            _ => Err(nekoton_token_unpacker::UnpackerError::InvalidAbi),
        }
    }
}

fn serialize_struct(
    container: &Container,
    fields: &[Field],
    struct_type: StructType,
) -> proc_macro2::TokenStream {
    let name = &container.ident;

    let build_fields = fields.iter().map(|f| {
        let name = f.original.ident.as_ref().unwrap();

        if is_abi(&f.original.attrs) {
            let field_name = match &f.attrs.name {
                Some(v) => v.clone(),
                None => name.to_string(),
            };

            let try_unpack = try_unpack(&f.attrs.type_name, &f.attrs.unpack_with);

            quote! {
                #name: {
                    let token = tokens.next();
                    let name = match &token {
                        Some(token) => token.name.clone(),
                        None => return Err(nekoton_token_unpacker::UnpackerError::InvalidAbi),
                    };
                    if name == #field_name {
                        #try_unpack
                    } else {
                        return Err(nekoton_token_unpacker::UnpackerError::InvalidName{
                            expected: #field_name.to_string(),
                            found: name,
                        });
                    }
                }
            }
        } else {
            quote! {
               #name: std::default::Default::default()
            }
        }
    });

    match struct_type {
        StructType::Plain => {
            quote! {
                let mut tokens = self.into_iter();

                std::result::Result::Ok(#name {
                    #(#build_fields,)*
                })
            }
        }
        StructType::Tuple => {
            quote! {
                let mut tokens = match self {
                    ton_abi::TokenValue::Tuple(tokens) => tokens.into_iter(),
                    _ => return Err(nekoton_token_unpacker::UnpackerError::InvalidAbi),
                };

                std::result::Result::Ok(#name {
                    #(#build_fields,)*
                })
            }
        }
    }
}

fn try_unpack(
    type_name: &Option<TypeName>,
    unpack_with: &Option<syn::Expr>,
) -> proc_macro2::TokenStream {
    match unpack_with {
        Some(data) => quote! {
            match token {
                Some(token) => #data(&token.value)?,
                None => return Err(nekoton_token_unpacker::UnpackerError::InvalidAbi),
            }
        },
        None => match type_name {
            Some(type_name) => {
                let handler = get_handler(type_name);
                quote! {
                    match token {
                        Some(token) => {
                            match token.value {
                                #handler
                                _ => return Err(nekoton_token_unpacker::UnpackerError::InvalidAbi),
                            }
                        },
                        None => return Err(nekoton_token_unpacker::UnpackerError::InvalidAbi),
                    }
                }
            }
            None => {
                quote! {
                    token.unpack()?
                }
            }
        },
    }
}

fn get_handler(type_name: &TypeName) -> proc_macro2::TokenStream {
    match type_name {
        TypeName::Int8 => {
            quote! {
                ton_abi::TokenValue::Int(ton_abi::Int { number: value, size: 8 }) => {
                    nekoton_token_unpacker::num_traits::ToPrimitive::to_i8(&value)
                    .ok_or(nekoton_token_unpacker::UnpackerError::InvalidAbi)?
                },
            }
        }
        TypeName::Uint8 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: value, size: 8 }) => {
                    nekoton_token_unpacker::num_traits::ToPrimitive::to_u8(&value)
                    .ok_or(nekoton_token_unpacker::UnpackerError::InvalidAbi)?
                },
            }
        }
        TypeName::Uint16 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: value, size: 16 }) => {
                    nekoton_token_unpacker::num_traits::ToPrimitive::to_u16(&value)
                    .ok_or(nekoton_token_unpacker::UnpackerError::InvalidAbi)?
                },
            }
        }
        TypeName::Uint32 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: value, size: 32 }) => {
                    nekoton_token_unpacker::num_traits::ToPrimitive::to_u32(&value)
                    .ok_or(nekoton_token_unpacker::UnpackerError::InvalidAbi)?
                },
            }
        }
        TypeName::Uint64 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: value, size: 64 }) => {
                    nekoton_token_unpacker::num_traits::ToPrimitive::to_u64(&value)
                    .ok_or(nekoton_token_unpacker::UnpackerError::InvalidAbi)?
                },
            }
        }
        TypeName::Uint128 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: value, size: 128 }) => {
                    nekoton_token_unpacker::num_traits::ToPrimitive::to_u128(&value)
                    .ok_or(nekoton_token_unpacker::UnpackerError::InvalidAbi)?
                },
            }
        }
        TypeName::Uint160 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: value, size: 160 }) => {
                    value
                },
            }
        }
        TypeName::Uint256 => {
            quote! {
                ton_abi::TokenValue::Uint(data) => {
                    let bytes = data.number.to_bytes_be();

                    let mut result = [0; 32];
                    let len = std::cmp::min(bytes.len(), 32);
                    let offset = 32 - len;
                    (0..len).for_each(|i| result[i + offset] = bytes[i]);

                    result.into()
                },
            }
        }
        TypeName::Address => {
            quote! {
                ton_abi::TokenValue::Address(ton_block::MsgAddress::AddrStd(addr)) => {
                    ton_block::MsgAddressInt::AddrStd(addr)
                },
                ton_abi::TokenValue::Address(ton_block::MsgAddress::AddrVar(addr)) => {
                    ton_block::MsgAddressInt::AddrVar(addr)
                },
            }
        }
        TypeName::Cell => {
            quote! {
                ton_abi::TokenValue::Cell(cell) => cell,
            }
        }
        TypeName::Bool => {
            quote! {
                ton_abi::TokenValue::Bool(value) => value,
            }
        }
        TypeName::Biguint128 => {
            quote! {
                ton_abi::TokenValue::Uint(ton_abi::Uint { number: value, size: 128 }) => {
                    value
                },
            }
        }
        TypeName::None => unreachable!(),
    }
}
