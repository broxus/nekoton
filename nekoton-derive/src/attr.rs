use proc_macro2::{Group, Span, TokenStream, TokenTree};
use quote::ToTokens;
use syn::Meta::*;
use syn::NestedMeta::*;

use crate::parsing_context::*;
use crate::symbol::*;

pub struct Container {
    pub enum_bool: bool,
}

impl Container {
    pub fn from_ast(cx: &ParsingContext, input: &syn::DeriveInput) -> Option<Self> {
        let mut enum_bool = BoolAttr::none(cx, ENUM_BOOL);

        for (from, meta_item) in input
            .attrs
            .iter()
            .flat_map(|attr| get_meta_items(cx, attr))
            .flat_map(|item| item.into_iter())
        {
            match (from, &meta_item) {
                (AttrFrom::Abi, Meta(Path(word))) if word == ENUM_BOOL => enum_bool.set_true(word),
                (AttrFrom::Abi, token) => {
                    cx.error_spanned_by(token, "unexpected token");
                    return None;
                }
            }
        }

        if let syn::Data::Struct(_) = input.data {
            if enum_bool.get() {
                cx.error_spanned_by(input, "Invalid attribute 'boolean' for struct");
            }
        }

        Some(Self {
            enum_bool: enum_bool.get(),
        })
    }
}

pub struct Field {
    pub name: Option<String>,
    pub type_name: Option<TypeName>,
    pub with: Option<syn::Expr>,
    pub pack_with: Option<syn::Expr>,
    pub unpack_with: Option<syn::Expr>,
}

impl Field {
    pub fn from_ast(cx: &ParsingContext, _index: usize, input: &syn::Field) -> Option<Self> {
        let mut name = Attr::none(cx, NAME);
        let mut type_name = Attr::none(cx, TYPE_NAME);
        let mut with = Attr::none(cx, WITH);
        let mut pack_with = Attr::none(cx, PACK_WITH);
        let mut unpack_with = Attr::none(cx, UNPACK_WITH);

        for (from, meta_item) in input
            .attrs
            .iter()
            .flat_map(|attr| get_meta_items(cx, attr))
            .flat_map(|item| item.into_iter())
        {
            match (from, &meta_item) {
                (AttrFrom::Abi, Meta(NameValue(m))) if m.path == NAME => {
                    if let Ok(s) = get_lit_str(cx, NAME, &m.lit) {
                        name.set(&m.path, s.value());
                    }
                }
                (AttrFrom::Abi, Meta(Path(word))) => {
                    if let Some(word) = word.get_ident() {
                        let pt = TypeName::from(&word.to_string());
                        if pt != TypeName::None {
                            type_name.set(word, pt);
                        } else {
                            cx.error_spanned_by(word, "unknown parse type")
                        }
                    }
                }
                (AttrFrom::Abi, Meta(NameValue(m))) if m.path == WITH => {
                    if let Ok(expr) = parse_lit_into_expr(cx, WITH, &m.lit) {
                        with.set(&m.path, expr);
                    }
                }
                (AttrFrom::Abi, Meta(NameValue(m))) if m.path == PACK_WITH => {
                    if let Ok(expr) = parse_lit_into_expr(cx, PACK_WITH, &m.lit) {
                        pack_with.set(&m.path, expr);
                    }
                }
                (AttrFrom::Abi, Meta(NameValue(m))) if m.path == UNPACK_WITH => {
                    if let Ok(expr) = parse_lit_into_expr(cx, UNPACK_WITH, &m.lit) {
                        unpack_with.set(&m.path, expr);
                    }
                }
                (AttrFrom::Abi, token) => {
                    cx.error_spanned_by(token, "unexpected token");
                    return None;
                }
            }
        }

        let type_name = type_name.get();
        let with = with.get();
        let pack_with = pack_with.get();
        let unpack_with = unpack_with.get();

        if !((type_name.is_none()
            && with.is_none()
            && pack_with.is_none()
            && unpack_with.is_none())
            || (type_name.is_some()
                && with.is_none()
                && pack_with.is_none()
                && unpack_with.is_none())
            || (type_name.is_none()
                && with.is_some()
                && pack_with.is_none()
                && unpack_with.is_none())
            || (type_name.is_none()
                && with.is_none()
                && (pack_with.is_some() || unpack_with.is_some())))
        {
            cx.error_spanned_by(input, "Only one of attributes ('type', 'with', 'pack_with/unpack_with') can be selected at time");
        }

        Some(Self {
            name: name.get(),
            type_name,
            with,
            pack_with,
            unpack_with,
        })
    }
}

fn parse_lit_into_expr(
    cx: &ParsingContext,
    attr_name: Symbol,
    lit: &syn::Lit,
) -> Result<syn::Expr, ()> {
    let string = get_lit_str(cx, attr_name, lit)?;
    parse_lit_str(string).map_err(|_| {
        cx.error_spanned_by(lit, format!("failed to parse expr: {:?}", string.value()))
    })
}

fn parse_lit_str<T>(s: &syn::LitStr) -> syn::parse::Result<T>
where
    T: syn::parse::Parse,
{
    let tokens = spanned_tokens(s)?;
    syn::parse2(tokens)
}

fn spanned_tokens(s: &syn::LitStr) -> syn::parse::Result<TokenStream> {
    let stream = syn::parse_str(&s.value())?;
    Ok(respan_token_stream(stream, s.span()))
}

fn respan_token_stream(stream: TokenStream, span: Span) -> TokenStream {
    stream
        .into_iter()
        .map(|token| respan_token_tree(token, span))
        .collect()
}

fn respan_token_tree(mut token: TokenTree, span: Span) -> TokenTree {
    if let TokenTree::Group(g) = &mut token {
        *g = Group::new(g.delimiter(), respan_token_stream(g.stream(), span));
    }
    token.set_span(span);
    token
}

#[allow(dead_code)]
fn get_lit_str_simple(lit: &syn::Lit) -> Result<&syn::LitStr, ()> {
    if let syn::Lit::Str(lit) = lit {
        Ok(lit)
    } else {
        Err(())
    }
}

fn get_lit_str<'a>(
    cx: &ParsingContext,
    attr_name: Symbol,
    lit: &'a syn::Lit,
) -> Result<&'a syn::LitStr, ()> {
    get_lit_str_special(cx, attr_name, attr_name, lit)
}

fn get_lit_str_special<'a>(
    cx: &ParsingContext,
    attr_name: Symbol,
    path_name: Symbol,
    lit: &'a syn::Lit,
) -> Result<&'a syn::LitStr, ()> {
    if let syn::Lit::Str(lit) = lit {
        Ok(lit)
    } else {
        cx.error_spanned_by(
            lit,
            format!(
                "expected {} attribute to be a string: `{} = \"...\"`",
                attr_name, path_name
            ),
        );
        Err(())
    }
}

fn get_meta_items(
    cx: &ParsingContext,
    attr: &syn::Attribute,
) -> Result<Vec<(AttrFrom, syn::NestedMeta)>, ()> {
    let attr_from = if attr.path == ABI {
        AttrFrom::Abi
    } else {
        return Ok(Vec::new());
    };

    match attr.parse_meta() {
        Ok(List(meta)) => Ok(meta
            .nested
            .into_iter()
            .map(|meta| (attr_from, meta))
            .collect()),
        Ok(Path(_)) => Ok(Vec::new()),
        Ok(other) => {
            cx.error_spanned_by(other, format!("expected #[{}(...)]", attr_from));
            Err(())
        }
        Err(err) => {
            cx.syn_error(err);
            Err(())
        }
    }
}

#[derive(Copy, Clone)]
enum AttrFrom {
    Abi,
}

impl std::fmt::Display for AttrFrom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttrFrom::Abi => f.write_str(ABI.inner()),
        }
    }
}

struct Attr<'c, T> {
    cx: &'c ParsingContext,
    name: Symbol,
    tokens: TokenStream,
    value: Option<T>,
}

impl<'c, T> Attr<'c, T> {
    fn none(cx: &'c ParsingContext, name: Symbol) -> Self {
        Attr {
            cx,
            name,
            tokens: TokenStream::new(),
            value: None,
        }
    }

    fn set<A: ToTokens>(&mut self, object: A, value: T) {
        let tokens = object.into_token_stream();

        if self.value.is_some() {
            self.cx
                .error_spanned_by(tokens, format!("duplicate abi attribute `{}`", self.name));
        } else {
            self.tokens = tokens;
            self.value = Some(value);
        }
    }

    #[allow(dead_code)]
    fn set_opt<A: ToTokens>(&mut self, object: A, value: Option<T>) {
        if let Some(value) = value {
            self.set(object, value);
        }
    }

    #[allow(dead_code)]
    fn set_if_none(&mut self, value: T) {
        if self.value.is_none() {
            self.value = Some(value);
        }
    }

    fn get(self) -> Option<T> {
        self.value
    }

    #[allow(dead_code)]
    fn get_with_tokens(self) -> Option<(TokenStream, T)> {
        match self.value {
            Some(value) => Some((self.tokens, value)),
            None => None,
        }
    }
}

struct BoolAttr<'c>(Attr<'c, ()>);

impl<'c> BoolAttr<'c> {
    fn none(cx: &'c ParsingContext, name: Symbol) -> Self {
        BoolAttr(Attr::none(cx, name))
    }

    fn set_true<A: ToTokens>(&mut self, object: A) {
        self.0.set(object, ());
    }

    fn get(&self) -> bool {
        self.0.value.is_some()
    }
}

#[derive(PartialEq)]
pub enum TypeName {
    Int8,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Bool,
    Cell,
    Address,
    String,
    Bytes,
    None,
}

impl TypeName {
    fn from(input: &str) -> TypeName {
        if input == "int8" {
            TypeName::Int8
        } else if input == "uint8" {
            TypeName::Uint8
        } else if input == "uint16" {
            TypeName::Uint16
        } else if input == "uint32" {
            TypeName::Uint32
        } else if input == "uint64" {
            TypeName::Uint64
        } else if input == "uint128" {
            TypeName::Uint128
        } else if input == "bool" {
            TypeName::Bool
        } else if input == "cell" {
            TypeName::Cell
        } else if input == "address" {
            TypeName::Address
        } else if input == "string" {
            TypeName::String
        } else if input == "bytes" {
            TypeName::Bytes
        } else {
            TypeName::None
        }
    }
}
