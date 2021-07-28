use ton_abi::Uint;

use nekoton_parser::abi::{
    BuildTokenValue, PackAbi, StandaloneToken, UnpackAbi, UnpackToken, UnpackerError,
    UnpackerResult,
};

#[derive(PackAbi, UnpackAbi, PartialEq, Debug)]
enum EventType {
    ETH = 0,
    TON = 1,
}

impl StandaloneToken for EventType {}

#[derive(PackAbi, UnpackAbi, PartialEq, Debug)]
#[abi(boolean)]
enum Voting {
    Reject = 0,
    Confirm = 1,
}

impl StandaloneToken for Voting {}

fn test_event_type() -> EventType {
    let event = EventType::TON;
    let token = event.token_value();
    let parsed: EventType = token.unpack().unwrap();
    parsed
}

fn test_voiting() -> Voting {
    let vote = Voting::Confirm;
    let token = vote.token_value();
    let parsed: Voting = token.unpack().unwrap();
    parsed
}

fn test_vec() -> Vec<EventType> {
    let eth_token = ton_abi::TokenValue::Uint(Uint::new(0, 8));
    let ton_token = ton_abi::TokenValue::Uint(Uint::new(1, 8));

    let tokens = ton_abi::Token::new(
        "types",
        ton_abi::TokenValue::Array(vec![eth_token, ton_token]),
    );

    let parsed: Vec<EventType> = tokens.unpack().unwrap();
    parsed
}

fn main() {
    let event = test_event_type();
    assert_eq!(event, EventType::TON);

    let vote = test_voiting();
    assert_eq!(vote, Voting::Confirm);

    let vec = test_vec();
    assert_eq!(vec[0], EventType::ETH);
    assert_eq!(vec[1], EventType::TON);
}
