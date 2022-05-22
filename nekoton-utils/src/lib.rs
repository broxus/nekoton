pub use self::address::*;
pub use self::clock::*;
#[cfg(feature = "encryption")]
pub use self::encryption::*;
pub use self::serde_helpers::*;
pub use self::traits::*;
pub use self::transaction::*;
pub use self::uint128::*;

mod address;
mod clock;
mod crc;
#[cfg(feature = "encryption")]
mod encryption;
mod serde_helpers;
mod traits;
mod transaction;
mod uint128;

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
