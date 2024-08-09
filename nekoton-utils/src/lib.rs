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

pub use self::address::*;
pub use self::cell::*;
pub use self::clock::*;
pub use self::crc::crc_16;
#[cfg(feature = "encryption")]
pub use self::encryption::*;
pub use self::serde_helpers::*;
pub use self::traits::*;
pub use self::transaction::*;

mod address;
mod cell;
mod clock;
mod crc;
#[cfg(feature = "encryption")]
mod encryption;
mod serde_helpers;
mod traits;
mod transaction;

#[macro_export]
macro_rules! define_string_enum {
    ($(#[$outer:ident $($outer_args:tt)*])* $vis:vis enum $type:ident { $($(#[$inner:ident $($inner_args:tt)*])* $variant:ident$( = $value:literal)?),*$(,)? }) => {
        $(#[$outer $($outer_args)*])*
        $vis enum $type {
            $($(#[$inner $($inner_args)*])* $variant$( = $value)?),*,
        }

        impl $type {
            #[inline(always)]
            $vis fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant)),*,
                }
            }
        }

        impl std::str::FromStr for $type {
            type Err = anyhow::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(match s {
                    $(stringify!($variant) => Self::$variant),*,
                    _ => return Err(::nekoton_utils::UnknownEnumVariant.into()),
                })
            }
        }

        impl std::fmt::Display for $type {
            fn fmt(&self, f: &'_ mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
#[error("Unknown enum variant")]
pub struct UnknownEnumVariant;
