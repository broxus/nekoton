use ton_abi::{Token, TokenValue, Uint};

use nekoton_abi::{PackAbi, UnpackAbi};

#[derive(PackAbi, UnpackAbi, PartialEq, Debug)]
enum EventType {
    ETH = 0,
    TON = 1,
}

#[derive(PackAbi, UnpackAbi, PartialEq, Debug)]
#[abi(boolean)]
enum Voting {
    Reject = 0,
    Confirm = 1,
}

#[derive(PackAbi, UnpackAbi)]
struct Test {
    #[abi(array, name = "eventTypes")]
    event_types: Vec<EventType>,
}

fn test_event_type() -> EventType {
    use nekoton_abi::BuildTokenValue;

    let event = EventType::TON;
    let token = event.token_value();
    let parsed: EventType = token.unpack().unwrap();
    parsed
}

fn test_voiting() -> Voting {
    use nekoton_abi::BuildTokenValue;

    let vote = Voting::Confirm;
    let token = vote.token_value();
    let parsed: Voting = token.unpack().unwrap();
    parsed
}

fn test() -> Test {
    let eth = TokenValue::Uint(Uint::new(0, 8));
    let ton = TokenValue::Uint(Uint::new(1, 8));
    let event_types = Token::new("eventTypes", TokenValue::Array(vec![eth, ton]));

    let tuple = Token::new("tuple", TokenValue::Tuple(vec![event_types]));

    let parsed: Test = tuple.unpack().unwrap();
    parsed
}

fn main() {
    let event = test_event_type();
    assert_eq!(event, EventType::TON);

    let vote = test_voiting();
    assert_eq!(vote, Voting::Confirm);

    let data = test();
    assert_eq!(data.event_types[0], EventType::ETH);
    assert_eq!(data.event_types[1], EventType::TON);
}
