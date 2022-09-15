use std::str::FromStr;

use std::collections::BTreeMap;
use ton_abi::{MapKeyTokenValue, ParamType, TokenValue};
use ton_abi::{Token, Uint};
use ton_block::{MsgAddress, MsgAddressInt};

use nekoton_abi::*;

#[derive(UnpackAbi, KnownParamType, Debug, PartialEq)]
struct VestingsComponents {
    #[abi(uint32, name = "remainingAmount")]
    remaining_amount: u32,
    #[abi(uint64, name = "lastWithdrawalTime")]
    last_withdrawal_time: u64,
    #[abi(uint32, name = "withdrawalPeriod")]
    withdrawal_period: u32,
    #[abi(uint64, name = "withdrawalValue")]
    withdrawal_value: u64,
    #[abi(address)]
    owner: MsgAddressInt,
}

#[derive(Debug, UnpackAbi)]
struct ParticipantInfo {
    #[abi(uint64)]
    total: u64,
    #[abi(uint32, name = "withdrawValue")]
    withdraw_value: u32,
    #[abi(bool)]
    reinvest: bool,
    #[abi(uint64)]
    reward: u64,
    #[abi]
    stakes: BTreeMap<u64, u64>,
    #[abi]
    vestings: BTreeMap<u64, VestingsComponents>,
}

fn test() -> ParticipantInfo {
    let total = Token::new("total", TokenValue::Uint(Uint::new(100, 64)));
    let withdraw_value = Token::new("withdrawValue", TokenValue::Uint(Uint::new(30, 32)));
    let reinvest = Token::new("reinvest", TokenValue::Bool(true));
    let reward = Token::new("reward", TokenValue::Uint(Uint::new(12, 64)));

    let mut stakes_bmap = BTreeMap::new();
    stakes_bmap.insert(
        MapKeyTokenValue::Uint(Uint::new(12, 64)),
        TokenValue::Uint(Uint::new(50, 64)),
    );

    let stakes = Token::new(
        "stakes",
        TokenValue::Map(
            ParamType::Uint(64),
            VestingsComponents::param_type(),
            stakes_bmap,
        ),
    );

    let vestings_remaining_amount =
        Token::new("remainingAmount", TokenValue::Uint(Uint::new(23, 32)));
    let vestings_last_withdrawal_time =
        Token::new("lastWithdrawalTime", TokenValue::Uint(Uint::new(33, 64)));
    let vestings_withdrawal_period =
        Token::new("withdrawalPeriod", TokenValue::Uint(Uint::new(42, 32)));
    let vestings_withdrawal_value =
        Token::new("withdrawalValue", TokenValue::Uint(Uint::new(15, 64)));
    let vestings_owner = Token::new(
        "owner",
        TokenValue::Address(MsgAddress::AddrStd(
            match MsgAddressInt::from_str(
                "0:18c99afffe13d3081370f77c10fc4d51bc54e52b8e181db6a0e8bb75456d91ff",
            )
            .unwrap()
            {
                MsgAddressInt::AddrStd(a) => a,
                MsgAddressInt::AddrVar(_) => unreachable!(),
            },
        )),
    );
    let vestings_tokens = vec![
        vestings_remaining_amount,
        vestings_last_withdrawal_time,
        vestings_withdrawal_period,
        vestings_withdrawal_value,
        vestings_owner,
    ];

    let mut vestings_bmap = BTreeMap::new();
    vestings_bmap.insert(
        MapKeyTokenValue::Uint(Uint::new(1, 64)),
        TokenValue::Tuple(vestings_tokens),
    );

    let vestings = Token::new(
        "vestings",
        TokenValue::Map(
            ParamType::Uint(64),
            VestingsComponents::param_type(),
            vestings_bmap,
        ),
    );

    let tokens = vec![total, withdraw_value, reinvest, reward, stakes, vestings];
    let tuple = Token::new("tuple", TokenValue::Tuple(tokens));

    let parsed: ParticipantInfo = tuple.unpack().unwrap();

    parsed
}

fn main() {
    let data = test();

    assert_eq!(data.total, 100);
    assert_eq!(data.withdraw_value, 30);
    assert!(data.reinvest);
    assert_eq!(data.reward, 12);
    assert_eq!(*data.stakes.get(&(12_u64)).unwrap(), 50);
    assert_eq!(
        *data.vestings.get(&(1_u64)).unwrap(),
        VestingsComponents {
            remaining_amount: 23,
            last_withdrawal_time: 33,
            withdrawal_period: 42,
            withdrawal_value: 15,
            owner: MsgAddressInt::from_str(
                "0:18c99afffe13d3081370f77c10fc4d51bc54e52b8e181db6a0e8bb75456d91ff",
            )
            .unwrap(),
        }
    );
}
