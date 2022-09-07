use ton_abi::{Param, ParamType};

use crate::utils::declare_function;

pub fn send_transaction() -> &'static ton_abi::Function {
    declare_function! {
        abi: v2_3,
        header: [pubkey, time, expire],
        name: "sendTransaction",
        inputs: vec![
            Param::new("dest", ParamType::Address),
            Param::new("value", ParamType::Uint(128)),
            Param::new("bounce", ParamType::Bool),
            Param::new("flags", ParamType::Uint(8)),
            Param::new("payload", ParamType::Cell),
        ],
        outputs: Vec::new(),
    }
}

macro_rules! declare_send_transaction_raw {
    ($($name:ident => [$($inputs:tt)*]),*,) => {
        $(pub fn $name() -> &'static ton_abi::Function {
            declare_function! {
                abi: v2_3,
                function_id: 0x169e3e11,
                header: [pubkey, time, expire],
                name: "sendTransactionRaw",
                inputs: declare_send_transaction_raw!(@inputs [$($inputs)*] []),
                outputs: Vec::new(),
            }
        })*
    };

    (@inputs [] [$($inputs:tt)*]) => {
        vec![$($inputs)*]
    };
    (@inputs [$(,)? _ $($rest:tt)*] [$($inputs:tt)*]) => {
        declare_send_transaction_raw!(@inputs [$($rest)*] [
            $($inputs)*
            Param::new("flags", ParamType::Uint(8)),
            Param::new("message", ParamType::Cell),
        ])
    };
}

declare_send_transaction_raw! {
    send_transaction_raw_0 => [],
    send_transaction_raw_1 => [_],
    send_transaction_raw_2 => [_, _],
    send_transaction_raw_3 => [_, _, _],
    send_transaction_raw_4 => [_, _, _, _],
}
