use std::collections::hash_map;

use anyhow::{Context, Result};
use nekoton_utils::define_string_enum;
use rustc_hash::FxHashMap;
use ton_abi::contract::AbiVersion;
use ton_abi::{Token, TokenValue};
use ton_block::{Deserializable, GetRepresentationHash, TransactionDescr};
use ton_types::SliceData;

use super::read_function_id;

#[derive(Debug, Clone)]
/// Parses transactions with provided extractors
pub struct TransactionParser {
    abi_version: AbiVersion,
    headers: Vec<ton_abi::Param>,
    functions: FxHashMap<u32, WrappedFunction>,
    functions_with_bounce: FxHashMap<u32, FunctionWithBounceHandler>,
    events: FxHashMap<u32, ton_abi::Event>,
    match_external_in: bool,
}

impl TransactionParser {
    pub fn builder() -> TransactionParserBuilder {
        TransactionParserBuilder::default()
    }

    pub fn parse<'tx>(&'tx self, tx: &'tx ton_block::Transaction) -> Result<Vec<Extracted<'tx>>> {
        let mut output = Vec::new();

        if let Some(msg) = &tx.in_msg {
            let msg = msg.read_struct().context("Failed reading in msg")?;

            if let Some(body) = msg.body() {
                output.extend(self.parse_in_message(&msg, body)?.map(|parsed| Extracted {
                    function_id: parsed.function_id,
                    name: parsed.name,
                    bounced: parsed.bounced,
                    tokens: parsed.tokens,
                    message: msg,
                    tx,
                    is_in_message: true,
                    index_in_transaction: 0,
                    parsed_type: ParsedType::FunctionInput,
                    decoded_headers: parsed.headers,
                }));
            }
        }

        let mut index_in_transaction = 0;
        tx.out_msgs.iterate_slices(|slice| {
            let (body, message) = match slice
                .reference(0)
                .and_then(ton_block::Message::construct_from_cell)
                .map(|message| (message.body(), message))
            {
                Ok((Some(body), message)) => (body, message),
                _ => return Ok(true),
            };

            let function_id = read_function_id(&body)?;
            output.extend(
                self.parse_out_message(message.header(), function_id, body)?
                    .map(|parsed| Extracted {
                        function_id,
                        name: parsed.name,
                        bounced: false,
                        tokens: parsed.tokens,
                        message,
                        tx,
                        is_in_message: false,
                        index_in_transaction,
                        parsed_type: parsed.parsed_type,
                        decoded_headers: Default::default(),
                    }),
            );
            index_in_transaction += 1;
            Ok(true)
        })?;

        Ok(output)
    }

    fn parse_in_message(
        &self,
        message: &ton_block::Message,
        mut body: SliceData,
    ) -> Result<Option<ParsedInMessage<'_>>> {
        if matches!(
            message.header(), ton_block::CommonMsgInfo::ExtInMsgInfo(_)
            if self.match_external_in
        ) {
            let (headers, function_id, body) =
                ton_abi::Function::decode_header(&self.abi_version, body, &self.headers, false)?;

            return if let Some(fun) = self.functions.get(&function_id) {
                let tokens = TokenValue::decode_params(
                    fun.function.input_params(),
                    body,
                    &self.abi_version,
                    false,
                )?;

                Ok(Some(ParsedInMessage {
                    function_id,
                    name: &fun.function.name,
                    bounced: false,
                    tokens,
                    headers,
                }))
            } else {
                Ok(None)
            };
        }

        if message.bounced() {
            body.get_next_u32()?; //skip bounce bytes
            let function_id = read_function_id(&body)?;
            if let Some(abi) = self.functions_with_bounce.get(&function_id) {
                return Ok(Some(ParsedInMessage {
                    name: &abi.function.name,
                    function_id,
                    headers: Default::default(),
                    tokens: (abi.bounce_handler)(body)?,
                    bounced: true,
                }));
            }
        }

        let function_id = read_function_id(&body)?;
        match self.functions.get(&function_id) {
            Some(abi) => Ok(Some(ParsedInMessage {
                name: &abi.function.name,
                function_id,
                headers: Default::default(),
                tokens: abi
                    .decode_input(body, message.is_internal())
                    .context("Failed decoding input message")?,
                bounced: false,
            })),
            None => Ok(None),
        }
    }

    fn parse_out_message(
        &self,
        info: &ton_block::CommonMsgInfo,
        function_id: u32,
        body: SliceData,
    ) -> Result<Option<ParsedOutMessage<'_>>> {
        let is_internal = match info {
            ton_block::CommonMsgInfo::ExtOutMsgInfo(_) => {
                if let Some(event) = self.events.get(&function_id) {
                    return Ok(Some(ParsedOutMessage {
                        name: &event.name,
                        parsed_type: ParsedType::Event,
                        tokens: event.decode_input(body)?,
                    }));
                }

                false
            }
            ton_block::CommonMsgInfo::IntMsgInfo(_) => true,
            ton_block::CommonMsgInfo::ExtInMsgInfo(_) => return Ok(None),
        };

        Ok(if let Some(abi) = self.functions.get(&function_id) {
            let (parsed_type, tokens) = if abi.function.input_id == function_id {
                (
                    ParsedType::FunctionInput,
                    abi.decode_input(body, is_internal),
                )
            } else {
                (
                    ParsedType::FunctionOutput,
                    abi.decode_output(body, is_internal),
                )
            };

            Some(ParsedOutMessage {
                name: &abi.function.name,
                parsed_type,
                tokens: tokens.context("Failed decoding output message")?,
            })
        } else {
            None
        })
    }

    pub fn get_function(&self, function_id: u32) -> Option<&WrappedFunction> {
        self.functions.get(&function_id)
    }

    pub fn get_bounce_handler(&self, function_id: u32) -> Option<&FunctionWithBounceHandler> {
        self.functions_with_bounce.get(&function_id)
    }
}

#[derive(Default)]
pub struct TransactionParserBuilder {
    functions_in: Vec<WrappedFunction>,
    functions_out: Vec<WrappedFunction>,
    functions_with_bounce: Vec<FunctionWithBounceHandler>,
    events: Vec<ton_abi::Event>,
}

impl TransactionParserBuilder {
    /// Matches all messages with in function_id.
    /// # Params:
    /// * 'allow_partial_match' - if true, won't return error if there are unparsed bytes left in the message. Set false by default.
    pub fn function_input(
        mut self,
        function: ton_abi::Function,
        allow_partial_match: bool,
    ) -> Self {
        self.functions_in
            .push(WrappedFunction::new(function, allow_partial_match));
        self
    }

    /// Matches all messages with out function_id
    /// # Params:
    /// * 'allow_partial_match' - if true, won't return error if there are unparsed bytes left in the message. Set false by default.
    pub fn function_output(
        mut self,
        function: ton_abi::Function,
        allow_partial_match: bool,
    ) -> Self {
        self.functions_out
            .push(WrappedFunction::new(function, allow_partial_match));
        self
    }

    /// Matches in messages with function_id and applies bounce handler
    pub fn function_bounce(mut self, function: FunctionWithBounceHandler) -> Self {
        self.functions_with_bounce.push(function);
        self
    }

    /// Matches out messages with event_id
    pub fn event(mut self, event: ton_abi::Event) -> Self {
        self.events.push(event);
        self
    }

    pub fn function_in_list<I>(mut self, functions: I, allow_partial_match: bool) -> Self
    where
        I: IntoIterator<Item = ton_abi::Function>,
    {
        self.functions_in.extend(
            functions
                .into_iter()
                .map(|f| WrappedFunction::new(f, allow_partial_match)),
        );
        self
    }

    pub fn functions_out_list<I>(mut self, functions: I, allow_partial_match: bool) -> Self
    where
        I: IntoIterator<Item = ton_abi::Function>,
    {
        self.functions_out.extend(
            functions
                .into_iter()
                .map(|f| WrappedFunction::new(f, allow_partial_match)),
        );
        self
    }

    pub fn events_list<I>(mut self, events: I) -> Self
    where
        I: IntoIterator<Item = ton_abi::Event>,
    {
        self.events.extend(events);
        self
    }

    /// Returns `Err` if there are duplicate function_ids
    pub fn build(self) -> Result<TransactionParser> {
        self.build_impl(false)
    }

    /// Returns `Err` if there are duplicate function_ids or different contracts are used
    pub fn build_with_external_in(self) -> Result<TransactionParser> {
        self.build_impl(true)
    }

    /// Returns `Err` if there are duplicate function_ids
    /// # Params:
    /// * `match_external_in` - if true, `ExternalIn` messages will be matched. Not compatible with several different contracts.
    fn build_impl(self, match_external_in: bool) -> Result<TransactionParser> {
        let mut abi_version = None;
        let mut headers = Vec::new();

        let mut functions = FxHashMap::default();
        let mut functions_with_bounce = FxHashMap::default();
        let mut events = FxHashMap::default();

        let mut set_abi_version = |new_version| match abi_version {
            Some(version) if version == new_version => Ok(()),
            Some(_) => anyhow::bail!("Multiple different ABI versions"),
            None => {
                abi_version = Some(new_version);
                Ok(())
            }
        };
        let mut set_headers = |new_headers: &mut Vec<ton_abi::Param>| {
            if !match_external_in {
                return Ok(());
            }

            new_headers.sort_unstable_by(|a, b| a.name.cmp(&b.name));
            if headers.is_empty() {
                headers = new_headers.clone();
                Ok(())
            } else if headers.len() != new_headers.len()
                || headers
                    .iter()
                    .zip(new_headers.iter())
                    .any(|(a, b)| a.name != b.name)
            {
                Err(anyhow::anyhow!("Different headers sets are not supported"))
            } else {
                Ok(())
            }
        };

        for mut abi in self.functions_in {
            set_abi_version(abi.function.abi_version)?;
            set_headers(&mut abi.function.header)?;

            match functions.entry(abi.function.input_id) {
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(abi);
                }
                hash_map::Entry::Occupied(entry) => {
                    let WrappedFunction { function, .. } = entry.get();
                    anyhow::bail!(
                        "Duplicate function id for IN function. Id: {}. Name: {}",
                        function.input_id,
                        function.name,
                    )
                }
            }
        }

        for mut abi in self.functions_out {
            set_abi_version(abi.function.abi_version)?;
            set_headers(&mut abi.function.header)?;

            match functions.entry(abi.function.output_id) {
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(abi);
                }
                hash_map::Entry::Occupied(entry) => {
                    let WrappedFunction { function, .. } = entry.get();
                    if function.input_id == function.output_id {
                        log::warn!(
                            "Function with same input and output id: {}. \
                            Adding it only as IN function parser",
                            abi.function.name
                        );
                        continue;
                    }
                    anyhow::bail!(
                        "Duplicate function id for OUT function. Id: {}. Name: {}",
                        function.output_id,
                        function.name
                    )
                }
            }
        }

        for abi in self.functions_with_bounce {
            set_abi_version(abi.function.abi_version)?;

            match functions_with_bounce.entry(abi.function.input_id) {
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(abi);
                }
                hash_map::Entry::Occupied(entry) => {
                    let FunctionWithBounceHandler { function, .. } = entry.get();
                    anyhow::bail!(
                        "Duplicate function id for function with bounce. Id: {}. Name: {}",
                        function.input_id,
                        function.name
                    )
                }
            }
        }

        for event in self.events {
            set_abi_version(event.abi_version)?;

            match events.entry(event.id) {
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(event);
                }
                hash_map::Entry::Occupied(entry) => {
                    let event = entry.get();
                    anyhow::bail!("Duplicate event id. Id: {}. Name: {}", event.id, event.name);
                }
            }
        }

        Ok(TransactionParser {
            abi_version: abi_version.context("Matching functions list is empty")?,
            headers,
            functions,
            functions_with_bounce,
            events,
            match_external_in,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FunctionWithBounceHandler {
    function: ton_abi::Function,
    bounce_handler: BounceHandler,
}

impl FunctionWithBounceHandler {
    pub fn new(function: ton_abi::Function, bounce_handler: BounceHandler) -> Self {
        Self {
            function,
            bounce_handler,
        }
    }
}

pub type BounceHandler = fn(SliceData) -> Result<Vec<Token>>;

define_string_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
     pub enum ParsedType {
        FunctionInput,
        FunctionOutput,
        BouncedFunction,
        Event,
    }
}

#[derive(Debug)]
pub struct Extracted<'a> {
    pub function_id: u32,
    pub name: &'a str,
    pub bounced: bool,
    pub tokens: Vec<Token>,
    pub message: ton_block::Message,
    pub tx: &'a ton_block::Transaction,
    // TODO: change into `is_out`
    pub is_in_message: bool,
    /// The index of the message in the transaction
    pub index_in_transaction: u16,
    pub parsed_type: ParsedType,
    pub decoded_headers: Vec<Token>,
}

impl Extracted<'_> {
    pub fn transaction_hash(&self) -> Result<[u8; 32]> {
        Ok(*self.tx.hash()?.as_slice())
    }

    pub fn transaction_sender(&self) -> Option<ton_block::MsgAddressInt> {
        if let Some(message) = &self.tx.in_msg {
            message.read_struct().ok()?.src()
        } else {
            None
        }
    }

    pub fn message_recipient(&self) -> Option<ton_block::MsgAddressInt> {
        self.message.dst()
    }

    pub fn success(&self) -> bool {
        let res = self.tx.description.read_struct().map(|x| match x {
            TransactionDescr::Ordinary(a) => !a.aborted,
            _ => false,
        });
        res.unwrap_or(false)
    }

    pub fn into_owned(self) -> ExtractedOwned {
        ExtractedOwned {
            function_id: self.function_id,
            name: self.name.to_owned(),
            bounced: self.bounced,
            tokens: self.tokens,
            message: self.message,
            tx: self.tx.clone(),
            is_in_message: self.is_in_message,
            parsed_type: self.parsed_type,
            decoded_headers: self.decoded_headers,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExtractedOwned {
    pub function_id: u32,
    pub name: String,
    pub bounced: bool,
    pub tokens: Vec<Token>,
    pub message: ton_block::Message,
    pub tx: ton_block::Transaction,
    /// The index of the message in the transaction
    pub is_in_message: bool,
    pub parsed_type: ParsedType,
    pub decoded_headers: Vec<Token>,
}

struct ParsedInMessage<'a> {
    name: &'a str,
    function_id: u32,
    headers: Vec<Token>,
    tokens: Vec<Token>,
    bounced: bool,
}

struct ParsedOutMessage<'a> {
    name: &'a str,
    parsed_type: ParsedType,
    tokens: Vec<Token>,
}

#[derive(Debug, Clone)]
pub struct WrappedFunction {
    pub function: ton_abi::Function,
    pub allow_partial_match: bool,
}

impl WrappedFunction {
    fn new(function: ton_abi::Function, allow_partial_match: bool) -> Self {
        Self {
            function,
            allow_partial_match,
        }
    }

    pub fn decode_input(&self, data: SliceData, internal: bool) -> Result<Vec<Token>> {
        if self.allow_partial_match {
            self.function.decode_input_partial(data, internal)
        } else {
            self.function.decode_input(data, internal)
        }
    }

    pub fn decode_output(&self, data: SliceData, internal: bool) -> Result<Vec<Token>> {
        if self.allow_partial_match {
            self.function.decode_output_partial(data, internal)
        } else {
            self.function.decode_output(data, internal)
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use nekoton_contracts::{tip3, tip3_1};
    use ton_abi::{Token, TokenValue, Uint};
    use ton_block::{Deserializable, Transaction};
    use ton_types::SliceData;

    use crate::{
        transaction_parser::{FunctionWithBounceHandler, TransactionParser},
        EventBuilder, FunctionBuilder,
    };

    #[test]
    fn test_builder() {
        let fun = FunctionBuilder::new("kek").build();
        let evt = EventBuilder::new("kek").build();

        super::TransactionParserBuilder::default()
            .function_input(fun, false)
            .event(evt)
            .build()
            .unwrap();
    }

    #[test]
    fn test_builder_fail() {
        let fun = FunctionBuilder::new("kek").build();
        if fun != fun {
            panic!("functions are not equal");
        }

        let test = super::TransactionParserBuilder::default()
            .function_input(fun.clone(), false)
            .function_input(fun, false)
            .build();

        assert!(test.is_err());
    }

    fn prepare() -> [ton_abi::Event; 4] {
        let contract = ton_abi::Contract::load(DEX_ABI).unwrap();
        let mem = &contract.events;
        let id1 = mem.get("DepositLiquidity").unwrap();
        let parse_ev1 = contract.event_by_id(id1.id).unwrap();
        let id2 = mem.get("WithdrawLiquidity").unwrap();
        let parse_ev2 = contract.event_by_id(id2.id).unwrap();
        let id3 = mem.get("ExchangeLeftToRight").unwrap();
        let parse_ev3 = contract.event_by_id(id3.id).unwrap();
        let id4 = mem.get("ExchangeRightToLeft").unwrap();
        let parse_ev4 = contract.event_by_id(id4.id).unwrap();
        [
            parse_ev1.clone(),
            parse_ev2.clone(),
            parse_ev3.clone(),
            parse_ev4.clone(),
        ]
    }

    #[test]
    fn parse_event() {
        let evs = prepare();
        let tx = Transaction::construct_from_base64("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").unwrap();
        let parser = TransactionParser::builder()
            .events_list(evs)
            .build()
            .unwrap();
        let out = parser.parse(&tx).unwrap();

        assert_eq!(out.len(), 1);
        assert_eq!("DepositLiquidity", out[0].name);

        let tx = "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";
        let tx = Transaction::construct_from_base64(tx).unwrap();
        let out = parser.parse(&tx).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!("DepositLiquidity", out[0].name);
        assert_eq!(out[0].index_in_transaction, 1);
    }

    const TOKEN_WALLET: &str = include_str!("../test/token_wallet.json");
    const DEX_ABI: &str = include_str!("../test/dex_abi.json");

    #[test]
    fn send_tokens() {
        let fun: Vec<_> = ton_abi::contract::Contract::load(TOKEN_WALLET)
            .unwrap()
            .functions
            .into_values()
            .collect();

        let first_in = "te6ccgECDAEAAsMAA7V/5tfdn4snTzD3mpEERfYIzpH/ZUdEtsUp/JmiMK9gG9AAAKHxPVJkHHnLsYvGOOa5uIxUfoZp0N+7vh4tguxyvr/gpS/1sCrwAACh8RRQWBYDYtrgADR8rtkIBQQBAhcEaMkHc1lAGHtQrREDAgBvyZBpLEwrwvQAAAAAAAQAAgAAAALLrUKeztBOuHLLx1RWl1Y0S5Jz+55Kyp2jXbR1+dd1zEDQM8QAnkb+LB6EgAAAAAAAAAABSQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgnI8VM5MHnxQYZZPcO3rSmw4aUs1NG2EI7Ip1d/zYwWB3PV/8tK3PYU3SCLlQ6FjikeMS9eU3gtetXZuJ6wYRREvAgHgCgYBAd8HAbFoAfza+7PxZOnmHvNSIIi+wRnSP+yo6JbYpT+TNEYV7AN7AAHuDUXhWs1Sy11bGZj4BpfAOCMEC1zg//hNNgzw/eWmkHNIMnQGK8M2AAAUPieqTITAbFtcwAgB7RjSFwIAAAAAAAAAAAAAAAAAlw/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAEcSwzASifTNKv0V8EKwo04+co0+rRLLuqxzv3leScPaQAjiWGYCUT6ZpV+ivghWFGnHzlGn1aJZd1WOd+8ryTh7RCQAAAbFoARxLDMBKJ9M0q/RXwQrCjTj5yjT6tEsu6rHO/eV5Jw9pAD+bX3Z+LJ08w95qRBEX2CM6R/2VHRLbFKfyZojCvYBvUHc1lAAGIavcAAAUPidOvwTAbFtKwAsAi3sBdBeAAPcGovCtZqllrq2MzHwDS+AcEYIFrnB//CabBnh+8tNAAAAAAAAAAAAAAAAAEuH8AAAAAAAAAAAAAAAAAAAAABA=";
        let second_in = "te6ccgECCwEAAnsAA7d+o/i0drPNLp1Aqpqvp7mPj9ZBwuent2axPfCACL5jU9AAAOos5hsoNsnwWbHWWcN3vuAKJG7kkh0oyCea7U3eRRBj3RxxsW6wAADqLOYbKBYOdIKQADSAJw24CAUEAQIXBAkExiz0GIAmavYRAwIAb8mHoSBMFFhAAAAAAAAEAAIAAAACf8Vu1SbfckG3GDgjpIaVYS57+yQguN2E/l7uma99s55AUBYMAJ5J1cwTjggAAAAAAAAAATEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIJyniWiC5OTUu3Taq+jrROnx1X2atnLFC55gWwUdNv1g4yXTRZaUGOAsZMdZkICn4dvIuFAKLLBpSE2IqxVcP3gbwIB4AgGAQHfBwCxaAHUfxaO1nml06gVU1X09zHx+sg4XPT27NYnvhABF8xqewAjiWGYCUT6ZpV+ivghWFGnHzlGn1aJZd1WOd+8ryTh7RBHV/v4BhRYYAAAHUWcw2UIwc6QUkABsWgANX0wLMj6oT6zQ9W4oAyYcD7Cxnoi0AXAZhQxeAyakXcAOo/i0drPNLp1Aqpqvp7mPj9ZBwuent2axPfCACL5jU9QTGLPQAYrwzYAAB1FnCrOhsHOkDTACQHtGNIXAgAAAAAAAAAAAAAAAAf4U8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIARxLDMBKJ9M0q/RXwQrCjTj5yjT6tEsu6rHO/eV5Jw9pACOJYZgJRPpmlX6K+CFYUacfOUafVoll3VY537yvJOHtEKAAA=";
        let first_out = "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";
        let second_out = "te6ccgECBwEAAZsAA7Vxq+mBZkfVCfWaHq3FAGTDgfYWM9EWgC4DMKGLwGTUi7AAAOos6eu4FSmzDnoaDRnjP8Ac/rnkJgqA6BSV+Q8j/9dHQUKWv0JQAADqLOFWdBYOdIMgABRpucMIBQQBAhcMSAkBa6yWGGm5vxEDAgBbwAAAAAAAAAAAAAAAAS1FLaRJ5QuM990nhh8UYSKv4bVGu4tw/IIW8MYUE5+OBACeQn1sBdGcAAAAAAAAAAB/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCco4WsVzUu58EKc/wM6HiEQtweqf+WzkudRJx5E203Wm5EsY1HZ4XMaQeR0fLT2T0mII6avap960GwJbDnWDZ/cQBAaAGAMFYAdR/Fo7WeaXTqBVTVfT3MfH6yDhc9Pbs1ie+EAEXzGp7AAavpgWZH1Qn1mh6txQBkw4H2FjPRFoAuAzChi8Bk1Iu0Ba6yWAGFFhgAAAdRZzDZQTBzpBSf////7Rar5/A";

        let txs: Vec<_> = [first_in, second_in, first_out, second_out]
            .iter()
            .map(|x| Transaction::construct_from_base64(x).unwrap())
            .collect();
        let parser = TransactionParser::builder()
            .function_in_list(fun.clone(), false)
            .functions_out_list(fun, false)
            .build()
            .unwrap();

        let out = parser.parse(&txs[0]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "internalTransfer");

        let out = parser.parse(&txs[1]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "internalTransfer");
        let out = parser.parse(&txs[2]).unwrap();

        assert_eq!(out.len(), 3);
        dbg!(&out);
        assert_eq!(out[0].name, "transferToRecipient");
        assert_eq!(out[1].name, "constructor");
        assert_eq!(out[2].name, "internalTransfer");
    }

    #[test]
    fn test_out() {
        let tx = "te6ccgECawEAGpAAA7d3R81ilMi1ZC8D8UBRd5ab6v2O/9wZg+JC26KF2AW/u5AAAO9wW9QQGJ4XCvvtAA9GJOUUfAcyX2PvXLeXairIqqumB/q1AugwAADtYXna6BYPRPaAAFSAUjMDaAUEAQIdDMGwAYkHc1lAGIAuG7YRAwIAc8oBpvlAUARn6ZQAAAAAAAYAAgAAAAWXzCNs0dVJ3HFsaCv5epPPu8dFD/xTza1TNWq+3VBVvlgVjZwAnkvNzB6EgAAAAAAAAAABlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgnLWcEG2yK7/sXdBBhaOxT3/VXRG1fjtZBvAZEywfWEENmqqF749gb6JzB3fRVxuknBk5qAdERiTo9CDzVOV9kVKAgHgZwYCAd0KBwEBIAgBsWgA6PmsUpkWrIXgfigKLvLTfV+x3/uDMHxIW3RQuwC393MAPHGCSe0cnJbLlDvwWVAMQStinhmUli5+gKGEr1o+Rv+QTEfPKAYrwzYAAB3uC3qCBsHontDACQHtGNIXAgAAAAAAAAAAAAAAAAACRUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIARxLDMBKJ9M0q/RXwQrCjTj5yjT6tEsu6rHO/eV5Jw9pACOJYZgJRPpmlX6K+CFYUacfOUafVoll3VY537yvJOHtFqAQEgCwG7aADo+axSmRasheB+KAou8tN9X7Hf+4MwfEhbdFC7ALf3cwA8cYJJ7RyclsuUO/BZUAxBK2KeGZSWLn6AoYSvWj5G/5AX14QACAQ8LQAAAB3uC3qCBMHontGaLVfP4AwCATQWDQEBwA4CA89gEA8ARNQAGMma//4T0wgTcPd8EPxNUbxU5SuOGB22oOi7dUVtkf8CASATEQIBIBIVAQEgFgIBIBUUAEMgA6jbcRNDxI3uC4NkbI37uUCRv7op6T7hiDYyB2Cy0VX8AEEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACASECx/vFFhyN+RSxnBfhtoUXEgn6/JIACZssH8iH1ZXSrjAA30pCCK7VP0oBgXAQr0pCD0oWoCASAcGQEC/xoC/n+NCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAT4aSHbPNMAAY4dgQIA1xgg+QEB0wABlNP/AwGTAvhC4iD4ZfkQ8qiV0wAB8nri0z8Bjh34QyG5IJ8wIPgjgQPoqIIIG3dAoLnekyD4Y+DyNNgw0x8B+CO88rkmGwIW0x8B2zz4R26OgN4fHQNu33Ai0NMD+kAw+GmpOAD4RH9vcYIImJaAb3Jtb3Nwb3T4ZI6A4CHHANwh0x8h3QHbPPhHbo6A3l0fHQEGW9s8HgIO+EFu4wDbPGZeBFggghAML/INu46A4CCCECnEiX67joDgIIIQS/Fg4ruOgOAgghB5sl7hu46A4FE9KSAUUFV+U/G9cMXNkKeC6eeB9m4Xwqk1OvPbuVh4LwhbFhZ8AAQgghBotV8/uuMCIIIQce7odbrjAiCCEHVszfe64wIgghB5sl7huuMCJSQjIQLqMPhBbuMA0x/4RFhvdfhk0fhEcG9ycG9xgEBvdPhk+Er4TPhN+E74UPhR+FJvByHA/45CI9DTAfpAMDHIz4cgzoBgz0DPgc+DyM+T5sl7hiJvJ1UGJ88WJs8L/yXPFiTPC3/IJM8WI88WIs8KAGxyzc3JcPsAZiIBvo5W+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPg8j4RG8VzwsfIm8nVQYnzxYmzwv/Jc8WJM8Lf8gkzxYjzxYizwoAbHLNzcn4RG8U+wDiMOMAf/hnXgPiMPhBbuMA0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZPhN+kJvE9cL/8MAjoCS+ADibfhv+E36Qm8T1wv/jhX4ScjPhYjOgG3PQM+Bz4HJgQCA+wDe2zx/+GdmWl4CsDD4QW7jAPpBldTR0PpA39cMAJXU0dDSAN/R+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8uBk+AAh+HAg+HJb2zx/+GdmXgLiMPhBbuMA+Ebyc3H4ZtH4TPhCuiCOFDD4TfpCbxPXC//AACCVMPhMwADf3vLgZPgAf/hy+E36Qm8T1wv/ji34TcjPhYjOjQPInEAAAAAAAAAAAAAAAAABzxbPgc+Bz5EhTuze+ErPFslx+wDe2zx/+GcmXgGS7UTQINdJwgGOPNP/0z/TANX6QPpA+HH4cPht+kDU0//Tf/QEASBuldDTf28C3/hv1woA+HL4bvhs+Gv4an/4Yfhm+GP4Yo6A4icB/vQFcSGAQPQOjiSNCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATf+GpyIYBA9A+SyMnf+GtzIYBA9A6T1wv/kXDi+Gx0IYBA9A6OJI0IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABN/4bXD4bm0oAM74b40IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABPhwjQhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE+HFw+HJwAYBA9A7yvdcL//hicPhjcPhmf/hhE0C5ncmuRDcN75RqEUtkosn1BTapw+VmXclDiJo+NB0zswAHIIIQPxDRq7uOgOAgghBJaVh/u46A4CCCEEvxYOK64wI1LioC/jD4QW7jAPpBldTR0PpA39cNf5XU0dDTf9/XDX+V1NHQ03/f+kGV1NHQ+kDf1wwAldTR0NIA39TR+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8uBkJMIA8uBkJPhOu/LgZSX6Qm8T1wv/wwBmKwIy8uBvJfgoxwWz8uBv+E36Qm8T1wv/wwCOgC0sAeSOaPgnbxAkvPLgbiOCCvrwgLzy4G74ACT4TgGhtX/4biMmf8jPhYDKAHPPQM4B+gKAac9Az4HPg8jPkGNIXAomzwt/+EzPC//4Tc8WJPpCbxPXC//DAJEkkvgo4s8WI88KACLPFM3JcfsA4l8G2zx/+GdeAe6CCvrwgPgnbxDbPKG1f7YJ+CdvECGCCvrwgKC1f7zy4G4gcvsCJfhOAaG1f/huJn/Iz4WAygBzz0DOgG3PQM+Bz4PIz5BjSFwKJ88Lf/hMzwv/+E3PFiX6Qm8T1wv/wwCRJZL4TeLPFiTPCgAjzxTNyYEAgfsAMGUCKCCCED9WeVG64wIgghBJaVh/uuMCMS8CkDD4QW7jANMf+ERYb3X4ZNH4RHBvcnBvcYBAb3T4ZPhOIcD/jiMj0NMB+kAwMcjPhyDOgGDPQM+Bz4HPkyWlYf4hzwt/yXD7AGYwAYCON/hEIG8TIW8S+ElVAm8RyHLPQMoAc89AzgH6AvQAgGjPQM+Bz4H4RG8VzwsfIc8Lf8n4RG8U+wDiMOMAf/hnXgT8MPhBbuMA+kGV1NHQ+kDf1w1/ldTR0NN/3/pBldTR0PpA39cMAJXU0dDSAN/U0fhPbrPy4Gv4SfhPIG7yf28RxwXy4Gwj+E8gbvJ/bxC78uBtI/hOu/LgZSPCAPLgZCT4KMcFs/Lgb/hN+kJvE9cL/8MAjoCOgOIj+E4BobV/ZjQzMgG0+G74TyBu8n9vECShtX/4TyBu8n9vEW8C+G8kf8jPhYDKAHPPQM6Abc9Az4HPg8jPkGNIXAolzwt/+EzPC//4Tc8WJM8WI88KACLPFM3JgQCB+wBfBds8f/hnXgIu2zyCCvrwgLzy4G74J28Q2zyhtX9y+wJlZQJyggr68ID4J28Q2zyhtX+2CfgnbxAhggr68ICgtX+88uBuIHL7AoIK+vCA+CdvENs8obV/tgly+wIwZWUCKCCCEC2pTS+64wIgghA/ENGruuMCPDYC/jD4QW7jANcN/5XU0dDT/9/6QZXU0dD6QN/XDX+V1NHQ03/f1w1/ldTR0NN/39cNf5XU0dDTf9/6QZXU0dD6QN/XDACV1NHQ0gDf1NH4TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y4GQlwgBmNwL88uBkJfhOu/LgZSb6Qm8T1wv/wAAglDAnwADf8uBv+E36Qm8T1wv/wwCOgI4g+CdvECUloLV/vPLgbiOCCvrwgLzy4G4n+Ey98uBk+ADibSjIy/9wWIBA9EP4SnFYgED0FvhLcliAQPQXKMjL/3NYgED0Qyd0WIBA9BbI9ADJOzgB/PhLyM+EgPQA9ADPgcmNCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQmwgCONyEg+QD4KPpCbxLIz4ZAygfL/8nQKCHIz4WIzgH6AoBpz0DPg8+DIs8Uz4HPkaLVfP7JcfsAMTGdIfkAyM+KAEDL/8nQMeL4TTkBuPpCbxPXC//DAI5RJ/hOAaG1f/huIH/Iz4WAygBzz0DOgG3PQM+Bz4PIz5BjSFwKKc8Lf/hMzwv/+E3PFib6Qm8T1wv/wwCRJpL4TeLPFiXPCgAkzxTNyYEAgfsAOgG8jlMn+E4BobV/+G4lIX/Iz4WAygBzz0DOAfoCgGnPQM+Bz4PIz5BjSFwKKc8Lf/hMzwv/+E3PFib6Qm8T1wv/wwCRJpL4KOLPFiXPCgAkzxTNyXH7AOJbXwjbPH/4Z14BZoIK+vCA+CdvENs8obV/tgn4J28QIYIK+vCAoLV/J6C1f7zy4G4n+E3HBbPy4G8gcvsCMGUB6DDTH/hEWG91+GTRdCHA/44jI9DTAfpAMDHIz4cgzoBgz0DPgc+Bz5K2pTS+Ic8LH8lw+wCON/hEIG8TIW8S+ElVAm8RyHLPQMoAc89AzgH6AvQAgGjPQM+Bz4H4RG8VzwsfIc8LH8n4RG8U+wDiMOMAf/hnXhNAS9O6i7V+7Gu0I63BJvo/YDYCVzmIO7+VQXjYyAYWBLQABSCCEBBHyQS7joDgIIIQGNIXAruOgOAgghApxIl+uuMCSUE+Av4w+EFu4wD6QZXU0dD6QN/6QZXU0dD6QN/XDX+V1NHQ03/f1w1/ldTR0NN/3/pBldTR0PpA39cMAJXU0dDSAN/U0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZCX6Qm8T1wv/wwDy4G8kZj8C9sIA8uBkJibHBbPy4G/4TfpCbxPXC//DAI6Ajlf4J28QJLzy4G4jggr68IByqLV/vPLgbvgAIyfIz4WIzgH6AoBpz0DPgc+DyM+Q/VnlRifPFibPC38k+kJvE9cL/8MAkSSS+CjizxYjzwoAIs8Uzclx+wDiXwfbPH/4Z0BeAcyCCvrwgPgnbxDbPKG1f7YJ+CdvECGCCvrwgHKotX+gtX+88uBuIHL7AifIz4WIzoBtz0DPgc+DyM+Q/VnlRijPFifPC38l+kJvE9cL/8MAkSWS+E3izxYkzwoAI88UzcmBAIH7ADBlAiggghAYbXO8uuMCIIIQGNIXArrjAkdCAv4w+EFu4wDXDX+V1NHQ03/f1w3/ldTR0NP/3/pBldTR0PpA3/pBldTR0PpA39cMAJXU0dDSAN/U0SH4UrEgnDD4UPpCbxPXC//AAN/y4HAkJG0iyMv/cFiAQPRD+EpxWIBA9Bb4S3JYgED0FyLIy/9zWIBA9EMhdFiAQPQWyPQAZkMDvsn4S8jPhID0APQAz4HJIPkAyM+KAEDL/8nQMWwh+EkhxwXy4Gck+E3HBbMglTAl+Ey93/Lgb/hN+kJvE9cL/8MAjoCOgOIm+E4BoLV/+G4iIJww+FD6Qm8T1wv/wwDeRkVEAciOQ/hQyM+FiM6Abc9Az4HPg8jPkWUEfub4KM8W+ErPFijPC38nzwv/yCfPFvhJzxYmzxbI+E7PC38lzxTNzc3JgQCA+wCOFCPIz4WIzoBtz0DPgc+ByYEAgPsA4jBfBts8f/hnXgEY+CdvENs8obV/cvsCZQE8ggr68ID4J28Q2zyhtX+2CfgnbxAhvPLgbiBy+wIwZQKsMPhBbuMA0x/4RFhvdfhk0fhEcG9ycG9xgEBvdPhk+E9us5b4TyBu8n+OJ3CNCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARvAuIhwP9mSAHujiwj0NMB+kAwMcjPhyDOgGDPQM+Bz4HPkmG1zvIhbyJYIs8LfyHPFmwhyXD7AI5A+EQgbxMhbxL4SVUCbxHIcs9AygBzz0DOAfoC9ACAaM9Az4HPgfhEbxXPCx8hbyJYIs8LfyHPFmwhyfhEbxT7AOIw4wB/+GdeAiggghAPAliquuMCIIIQEEfJBLrjAk9KA/Yw+EFu4wDXDX+V1NHQ03/f1w1/ldTR0NN/3/pBldTR0PpA3/pBldTR0PpA39TR+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8uBkJMIA8uBkJPhOu/LgZfhN+kJvE9cL/8MAII6A3iBmTksCYI4dMPhN+kJvE9cL/8AAIJ4wI/gnbxC7IJQwI8IA3t7f8uBu+E36Qm8T1wv/wwCOgE1MAcKOV/gAJPhOAaG1f/huI/hKf8jPhYDKAHPPQM4B+gKAac9Az4HPg8jPkLiiIqomzwt/+EzPC//4Tc8WJPpCbxPXC//DAJEkkvgo4s8WyCTPFiPPFM3NyXD7AOJfBds8f/hnXgHMggr68ID4J28Q2zyhtX+2CXL7AiT4TgGhtX/4bvhKf8jPhYDKAHPPQM6Abc9Az4HPg8jPkLiiIqomzwt/+EzPC//4Tc8WJPpCbxPXC//DAJEkkvhN4s8WyCTPFiPPFM3NyYEAgPsAZQEKMNs8wgBlAy4w+EFu4wD6QZXU0dD6QN/R2zzbPH/4Z2ZQXgC8+E36Qm8T1wv/wwAglzD4TfhJxwXeII4UMPhMwwAgnDD4TPhFIG6SMHDeut7f8uBk+E7AAPLgZPgAIMjPhQjOjQPID6AAAAAAAAAAAAAAAAABzxbPgc+ByYEAoPsAMBM+q9xefLFYQdC5zIlqpAyyM/2y6uNTSwbxSL+qQxOzzT8ABCCCCyHRc7uOgOAgghALP89Xu46A4CCCEAwv8g264wJXVFID/jD4QW7jANcNf5XU0dDTf9/6QZXU0dD6QN/6QZXU0dD6QN/U0fhK+EnHBfLgZiPCAPLgZCP4Trvy4GX4J28Q2zyhtX9y+wIj+E4BobV/+G74Sn/Iz4WAygBzz0DOgG3PQM+Bz4PIz5C4oiKqJc8Lf/hMzwv/+E3PFiTPFsgkzxZmZVMBJCPPFM3NyYEAgPsAXwTbPH/4Z14CKCCCEAXFAA+64wIgghALP89XuuMCVlUCVjD4QW7jANcNf5XU0dDTf9/R+Er4SccF8uBm+AAg+E4BoLV/+G4w2zx/+GdmXgKWMPhBbuMA+kGV1NHQ+kDf0fhN+kJvE9cL/8MAIJcw+E34SccF3iCOFDD4TMMAIJww+Ez4RSBukjBw3rre3/LgZPgAIPhxMNs8f/hnZl4CJCCCCXwzWbrjAiCCCyHRc7rjAltYA/Aw+EFu4wD6QZXU0dD6QN/XDX+V1NHQ03/f1w1/ldTR0NN/39H4TfpCbxPXC//DACCXMPhN+EnHBd4gjhQw+EzDACCcMPhM+EUgbpIwcN663t/y4GQhwAAgljD4T26zs9/y4Gr4TfpCbxPXC//DAI6AkvgA4vhPbrNmWlkBiI4S+E8gbvJ/bxAiupYgI28C+G/eliAjbwL4b+L4TfpCbxPXC/+OFfhJyM+FiM6Abc9Az4HPgcmBAID7AN5fA9s8f/hnXgEmggr68ID4J28Q2zyhtX+2CXL7AmUC/jD4QW7jANMf+ERYb3X4ZNH4RHBvcnBvcYBAb3T4ZPhLIcD/jiIj0NMB+kAwMcjPhyDOgGDPQM+Bz4HPkgXwzWYhzxTJcPsAjjb4RCBvEyFvEvhJVQJvEchyz0DKAHPPQM4B+gL0AIBoz0DPgc+B+ERvFc8LHyHPFMn4RG8U+wBmXAEO4jDjAH/4Z14EQCHWHzH4QW7jAPgAINMfMiCCEBjSFwK6joCOgOIwMNs8ZmFfXgCs+ELIy//4Q88LP/hGzwsAyPhN+FD4UV4gzs7O+Er4S/hM+E74T/hSXmDPEc7My//LfwEgbrOOFcgBbyLIIs8LfyHPFmwhzxcBz4PPEZMwz4HiygDJ7VQBFiCCEC4oiKq6joDeYAEwIdN/M/hOAaC1f/hu+E36Qm8T1wv/joDeYwI8IdN/MyD4TgGgtX/4bvhR+kJvE9cL/8MAjoCOgOIwZGIBGPhN+kJvE9cL/46A3mMBUIIK+vCA+CdvENs8obV/tgly+wL4TcjPhYjOgG3PQM+Bz4HJgQCA+wBlAYD4J28Q2zyhtX9y+wL4UcjPhYjOgG3PQM+Bz4PIz5DqFdlC+CjPFvhKzxYizwt/yPhJzxb4Ts8Lf83NyYEAgPsAZQAYcGim+2CVaKb+YDHfAH7tRNDT/9M/0wDV+kD6QPhx+HD4bfpA1NP/03/0BAEgbpXQ039vAt/4b9cKAPhy+G74bPhr+Gp/+GH4Zvhj+GIBsUgBHEsMwEon0zSr9FfBCsKNOPnKNPq0Sy7qsc795XknD2kAHR81ilMi1ZC8D8UBRd5ab6v2O/9wZg+JC26KF2AW/u5QdzWUAAYzAWYAAB3uCwBwBMHonsDAaAHrPxDRqwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/4AAAAAAAAAAAAAAAAABIqAAAAAAAAAAAAAAAAAC+vCAAAAAAAAAAAAAAAAAAAAAAEGkBQ4ARxLDMBKJ9M0q/RXwQrCjTj5yjT6tEsu6rHO/eV5Jw9ohqAAA=";
        let fun = ton_abi::contract::Contract::load(TOKEN_WALLET)
            .unwrap()
            .functions["internalTransfer"]
            .clone();
        let tx = Transaction::construct_from_base64(tx).unwrap();
        let parser = TransactionParser::builder()
            .function_input(fun, false)
            .build()
            .unwrap();

        let res = parser.parse(&tx).unwrap();
        assert_eq!(res.len(), 1);
    }

    fn bounce_handler(mut data: SliceData) -> Result<Vec<Token>> {
        let _id = data.get_next_u32()?;
        let token = data.get_next_u128()?;
        Ok(vec![Token::new(
            "amount",
            TokenValue::Uint(Uint::new(token, 128)),
        )])
    }

    #[test]
    fn test_bounce() {
        let tx = "te6ccgECCQEAAiEAA7V9jKvgMYxeLukedeW/PRr7QyRzEpkal33nb9KfgpelA3AAAO1mmxCMEy4UbEGiIQKVpE2nzO2Ar32k7H36ni1NMpxrcPorUNuwAADtZo+e3BYO9BHwADRwGMkIBQQBAhcMSgkCmI36GG92AhEDAgBvyYehIEwUWEAAAAAAAAQAAgAAAAKLF5Ge7DorMQ9dbEzZTgWK7Jiugap8s4dRpkiQl7CNEEBQFgwAnkP1TAqiBAAAAAAAAAAAtgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgnIBZa/nTbAD2Vcr8A6p+uT7XD4tLowmBLZEuIHLxU1zbeHGgHFi5dfeWnrNgtL3FHE6zw6ysjTJJI3LFFDAgPi3AgHgCAYBAd8HALFoAbGVfAYxi8XdI868t+ejX2hkjmJTI1LvvO36U/BS9KBvABgzjiRJUfoXsV99CuD/WnKK4QN5mlferMiVbk0Y3Jc3ECddFmAGFFhgAAAdrNNiEYTB3oI+QAD5WAHF6/YBDYNj7TABzedO3/4+ENpaE0PhwRx5NFYisFNfpQA2Mq+AxjF4u6R515b89GvtDJHMSmRqXfedv0p+Cl6UDdApiN+gBhRYYAAAHazSjHIEwd6CFH////+MaQuBAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAEA=";
        let tx = Transaction::construct_from_base64(tx).unwrap();
        let fun = ton_abi::contract::Contract::load(TOKEN_WALLET)
            .unwrap()
            .functions["internalTransfer"]
            .clone();
        // internalTransfer - 416421634 416421634
        let fun = FunctionWithBounceHandler::new(fun, bounce_handler);
        let parser = TransactionParser::builder()
            .function_bounce(fun)
            .build()
            .unwrap();

        dbg!(&parser);
        let res = parser.parse(&tx).unwrap();
        let amount = &res[0].tokens[0].value;
        assert_eq!("1", amount.to_string());
        assert!(res[0].bounced);
    }

    #[test]
    fn internal_transfer() {
        let tx = "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";
        let tx = Transaction::construct_from_base64(tx).unwrap();
        let fun = ton_abi::contract::Contract::load(TOKEN_WALLET)
            .unwrap()
            .functions["internalTransfer"]
            .clone();
        let parser = TransactionParser::builder()
            .function_input(fun, false)
            .build()
            .unwrap();
        let tokens = parser.parse(&tx).unwrap();
        assert_eq!(tokens.len(), 1);
        assert!(!tokens[0].is_in_message);

        let tx = "te6ccgECCwEAAnsAA7d0hHiv4yQasTjF06uPMW8sLJlVPnUAFJVaqw9OtXY7dnAAAVL2G2jcMZMl+6MAAm5PIBDJHX7w8+LiKlNkZ0T1s1p6A2lMSIfQAAFS9hto3BYfumKQADSAJw24CAUEAQIXBAkExiz0GIAmavYRAwIAb8mHoSBMFFhAAAAAAAAEAAIAAAACGI5v3Ahuxfbd3BS0ex/yYIsHyLoUSw1VH493Xze2RlRAUBYMAJ5J1cwTjggAAAAAAAAAATEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIJyk/ZgRtNDsjAlgiSjz1kaTVcRIp7tF481mibfiNEpQeNwdoS4huC2c/C840pcFlfBqpXN56N5rAAw8dIL6AcezAIB4AgGAQHfBwCxaACQjxX8ZINWJxi6dXHmLeWFkyqnzqACkqtVYenWrsduzwAjiWGYCUT6ZpV+ivghWFGnHzlGn1aJZd1WOd+8ryTh7RBHWGeABhRYYAAAKl7DbRuIw/dMUkABsWgANX0wLMj6oT6zQ9W4oAyYcD7Cxnoi0AXAZhQxeAyakXcAEhHiv4yQasTjF06uPMW8sLJlVPnUAFJVaqw9OtXY7dnQTGLPQAYrwzYAACpewxGOBsP3TELACQHtGNIXAgAAAAAAAAAAAAAAADuaygAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIARxLDMBKJ9M0q/RXwQrCjTj5yjT6tEsu6rHO/eV5Jw9pACOJYZgJRPpmlX6K+CFYUacfOUafVoll3VY537yvJOHtEKAAA=";
        let tx = Transaction::construct_from_base64(tx).unwrap();

        let tokens = parser.parse(&tx).unwrap();
        assert_eq!(tokens.len(), 1);
        assert!(tokens[0].is_in_message);
        assert_eq!(tokens[0].index_in_transaction, 0);
    }

    #[test]
    fn extracted_props() {
        let tx = "te6ccgECDQEAAyAAA7d2VB824ku5NceaZBGMw6rGxlQqN9/O1HgEwFCS8k2ZO9AAAVMVFx5wFNQvH4whj95/MxrcyudH6mIXPmtR9xuziONpG6+HmOsQAAFTC3uXxBYfv6+gADSALJZXKAUEAQIbBIi0iQ7dAwIYgCsusBEDAgBvyZCnrEwsaZwAAAAAAAQAAgAAAAPIj/VtEDN6Yxv6AoWwgfNOvZVXo/LBGUBGvEwXgDjVFEDQNMQAnksODDzhVAAAAAAAAAABfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgnIJ1rOS3KKtMH6NCJSBZtG8thfyDOR3FbomYzeDsV4hG+x3BF61v0LVJIazB4LT4lZqbgMkfW4F8KJziaf7H/JCAgHgCQYBAd8HAbFoAMqD5txJdya480yCMZh1WNjKhUb7+dqPAJgKEl5Jsyd7ADbkuzCNdLZjQqpjYdGVUxGiDlMoDYR2AC9i44IdlAh+EOflHMAGLGniAAAqYqLjzgTD9/X0wAgB7RjSFwIAAAAAAAAAAAAAAAAAACYxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAE5Vihmh7cbifKKrg6ZZhVQZurfljzEaw2QPagjzcnlzQAKNZrKwnj40tH1ZKNi8805q43R63HTLz9wzzOzd/QAWbDAGxaAE5Vihmh7cbifKKrg6ZZhVQZurfljzEaw2QPagjzcnlzQAZUHzbiS7k1x5pkEYzDqsbGVCo3387UeATAUJLyTZk71Dt0DAgBjOoEAAAKmKiiECGw/f14sAKAas/ENGrAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACABRrNZWE8fGlo+rJRsXnmnNXG6PW46ZefuGeZ2bv6ACzAAAAAAAAAAAAAAAAAAATGMAsBgwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAUazWVhPHxpaPqyUbF55pzVxuj1uOmXn7hnmdm7+gAs2AwACAAAAAA=";
        let tx = Transaction::construct_from_base64(tx).unwrap();
        let fun = ton_abi::contract::Contract::load(TOKEN_WALLET)
            .unwrap()
            .functions["internalTransfer"]
            .clone();
        let parser = TransactionParser::builder()
            .function_input(fun, false)
            .build()
            .unwrap();
        let token = parser.parse(&tx).unwrap().remove(0);
        assert_eq!(
            "0:db92ecc235d2d98d0aa98d8746554c4688394ca03611d800bd8b8e08765021f8",
            token.message_recipient().unwrap().to_string()
        );
        assert_eq!(
            "0:9cab143343db8dc4f94557074cb30aa833756fcb1e623586c81ed411e6e4f2e6",
            token.transaction_sender().unwrap().to_string()
        );
        assert!(!token.is_in_message);
        assert_eq!(
            token.transaction_hash().unwrap(),
            hex::decode("e60aa528fa05f1959960d099e3389abe42e3a210350c5e4a87e518974136f53b")
                .unwrap()
                .as_slice()
        );
        assert!(token.success());

        let tx = "te6ccgECCQEAAhUAA7V33dm+U37BKqMyPH84gieQ9gEkKbVl1DkuWUy3o/BnG/AAAVIf/RIoEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYflboQAD5gosIIAwIBAB8ECQLHmPIBwDBRYQMKLDBAAIJykK7Illr6uxbrw8ubQI665xthjXh4i8gNCYQ1k8rJjaSQrsiWWvq7FuvDy5tAjrrnG2GNeHiLyA0JhDWTysmNpAIB4AYEAQHfBQD5WAD7uzfKb9glVGZHj+cQRPIewCSFNqy6hyXLKZb0fgzjfwAjJ1VPtnxmoxtEIMno5sVjxhZlPEbk/jWsZqPh2RCfgJAsPIYgBhRYYAAAKkP/okUEw/K3Qn////+MaQuBAAAAAAAAAAAAAca/UmNAAAAAAAAAAAAAAAAAAEABsWgBGTqqfbPjNRjaIQZPRzYrHjCzKeI3J/GtYzUfDsiE/AUAH3dm+U37BKqMyPH84gieQ9gEkKbVl1DkuWUy3o/BnG/QLHmPIAYrwzYAACpD/0a3hMPytzLABwHtGNIXAgAAAAAAAAAAAAONfqTGgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAY5RGXuGtI1q+zl3Tv9Upy40cY+oTi+JDkfKiMma6+/fADHKIy9w1pGtX2cu6d/qlOXGjjH1CcXxIcj5URkzXX378IAAA=";
        let tx = Transaction::construct_from_base64(tx).unwrap();
        let token = parser.parse(&tx).unwrap().remove(0);
        assert!(!token.success());
        assert_eq!(token.name, "internalTransfer");
    }

    fn basic_tokens_parser() -> TransactionParser {
        // basic tip3
        let accept_transfer_basic = tip3::token_wallet_contract::accept_transfer();
        let accept_mint_basic = tip3::token_wallet_contract::accept_mint();
        let accept_burn_basic = tip3::root_token_contract::accept_burn();

        TransactionParser::builder()
            .function_input(accept_transfer_basic.clone(), true)
            .function_input(accept_mint_basic.clone(), true)
            .function_input(accept_burn_basic.clone(), true)
            .build()
            .unwrap()
    }

    #[test]
    fn test_partial_match() {
        let tx = "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";
        let tx = Transaction::construct_from_base64(tx).unwrap();
        let extractor = basic_tokens_parser();
        let parsed = extractor.parse(&tx).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].tokens.len(), 1);
    }

    fn tip_3_1_tokens_parser() -> TransactionParser {
        let accept_transfer = tip3_1::token_wallet_contract::accept_transfer();
        let accept_mint = tip3_1::token_wallet_contract::accept_mint();
        let accept_burn = tip3_1::root_token_contract::accept_burn();

        TransactionParser::builder()
            .function_input(accept_transfer.clone(), false)
            .function_input(accept_mint.clone(), false)
            .function_input(accept_burn.clone(), false)
            .build()
            .unwrap()
    }

    #[test]
    fn test_full_match() {
        let tx = "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";
        let tx = Transaction::construct_from_base64(tx).unwrap();
        let extractor = tip_3_1_tokens_parser();
        let parsed = extractor.parse(&tx).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].tokens.len(), 5);
    }

    #[test]
    fn test_full_contract() {
        let abi = r#"{"ABI version":2,"data":[{"key":1,"name":"_randomNonce","type":"uint256"}],"events":[{"inputs":[{"name":"previousOwner","type":"uint256"},{"name":"newOwner","type":"uint256"}],"name":"OwnershipTransferred","outputs":[]}],"fields":[{"name":"_pubkey","type":"uint256"},{"name":"_timestamp","type":"uint64"},{"name":"_constructorFlag","type":"bool"},{"name":"owner","type":"uint256"},{"name":"_randomNonce","type":"uint256"}],"functions":[{"inputs":[{"name":"dest","type":"address"},{"name":"value","type":"uint128"},{"name":"bounce","type":"bool"},{"name":"flags","type":"uint8"},{"name":"payload","type":"cell"}],"name":"sendTransaction","outputs":[]},{"inputs":[{"name":"newOwner","type":"uint256"}],"name":"transferOwnership","outputs":[]},{"inputs":[],"name":"constructor","outputs":[]},{"inputs":[],"name":"owner","outputs":[{"name":"owner","type":"uint256"}]},{"inputs":[],"name":"_randomNonce","outputs":[{"name":"_randomNonce","type":"uint256"}]}],"header":["time"],"version":"2.2"}"#;
        let abi = ton_abi::Contract::load(abi).unwrap();
        let events = abi.events.values().cloned();
        let funs = abi.functions.values().cloned().collect::<Vec<_>>();

        let parser = TransactionParser::builder()
            .function_in_list(funs.clone(), false)
            .functions_out_list(funs, false)
            .events_list(events)
            .build_with_external_in()
            .unwrap();

        let tx = "te6ccgECCwEAAm8AA7V++NnCdgsS7iubg2YKljkWMK+Nl4rodhkGdA6ME3X1l2AAAVf+pN2AHEqw3VLPrqWO4rwpNsyQj5WeGXAg+bV8rOllzOC4e0FwAAFX/qPpXBYglxvwADRw9u7oBQQBAg8MQEYbHIJEQAMCAG/JiqxsTBx2WAAAAAAAAgAAAAAAAh+1bvDWnLCgRmTLFrApyvKnoCvN5oGbiFWPDRqpjy0EQJAfZACdQy+jE4gAAAAAAAAAACSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIACCcj7pfRHC7sHIea84Hs/hukiSefxdzPwsH4Ne5GCMU2vSK9sdrhKJoUW6Md9cS31zzC4xsPaU5ULRh/WiRm/kBvoCAeAIBgEB3wcBsWgB3xs4TsFiXcVzcGzBUscixhXxsvFdDsMgzoHRgm6+su0ADXqbt4aynxEK1cyy5QQ+J7v5F3aeGaWPbVJjYUSyrwFR3IDsoAYcdoQAACr/1JuwBMQS437ACgHdiAHfGzhOwWJdxXNwbMFSxyLGFfGy8V0OwyDOgdGCbr6y7AV48xwh0kVSa89wWq/VOK3fnIvDljptTJeqcB10t2RV0KCx4Vq1k5kzaY0RhHBKxqT0tiyp/nC0e+1/jx19p/AwAAAF+9ORPq0zuZGyCQFlgAa9TdvDWU+IhWrmWXKCHxPd/Iu7TwzSx7apMbCiWVeAoAAAAAAAAAAAAAAADuaygBAICgBLDgTSnoAdQT3MtmUbh60b5nBYLKOECUJ+GUmxfw3N+6y3zjrx6BA=";
        let tx = Transaction::construct_from_base64(tx).unwrap();
        let res = parser.parse(&tx).unwrap();
        assert_eq!(res.len(), 1);
        let res = &res[0];
        assert_eq!(res.tokens.len(), 5);
        assert_eq!(res.decoded_headers.len(), 1);
    }

    #[test]
    fn test_full_2() {
        let abi = r#"{"ABI version": 2, "data": [{"key": 1, "name": "root_", "type": "address"}, {"key": 2, "name": "owner_", "type": "address"}], "events": [], "fields": [{"name": "_pubkey", "type": "uint256"}, {"name": "_timestamp", "type": "uint64"}, {"name": "_constructorFlag", "type": "bool"}, {"name": "root_", "type": "address"}, {"name": "owner_", "type": "address"}, {"name": "balance_", "type": "uint128"}], "functions": [{"inputs": [], "name": "constructor", "outputs": []}, {"inputs": [{"name": "answerId", "type": "uint32"}, {"name": "interfaceID", "type": "uint32"}], "name": "supportsInterface", "outputs": [{"name": "value0", "type": "bool"}]}, {"inputs": [{"name": "remainingGasTo", "type": "address"}], "name": "destroy", "outputs": []}, {"inputs": [{"name": "amount", "type": "uint128"}, {"name": "remainingGasTo", "type": "address"}, {"name": "callbackTo", "type": "address"}, {"name": "payload", "type": "cell"}], "name": "burnByRoot", "outputs": []}, {"inputs": [{"name": "amount", "type": "uint128"}, {"name": "remainingGasTo", "type": "address"}, {"name": "callbackTo", "type": "address"}, {"name": "payload", "type": "cell"}], "name": "burn", "outputs": []}, {"inputs": [{"name": "answerId", "type": "uint32"}], "name": "balance", "outputs": [{"name": "value0", "type": "uint128"}]}, {"inputs": [{"name": "answerId", "type": "uint32"}], "name": "owner", "outputs": [{"name": "value0", "type": "address"}]}, {"inputs": [{"name": "answerId", "type": "uint32"}], "name": "root", "outputs": [{"name": "value0", "type": "address"}]}, {"inputs": [{"name": "answerId", "type": "uint32"}], "name": "walletCode", "outputs": [{"name": "value0", "type": "cell"}]}, {"inputs": [{"name": "amount", "type": "uint128"}, {"name": "recipient", "type": "address"}, {"name": "deployWalletValue", "type": "uint128"}, {"name": "remainingGasTo", "type": "address"}, {"name": "notify", "type": "bool"}, {"name": "payload", "type": "cell"}], "name": "transfer", "outputs": []}, {"inputs": [{"name": "amount", "type": "uint128"}, {"name": "recipientTokenWallet", "type": "address"}, {"name": "remainingGasTo", "type": "address"}, {"name": "notify", "type": "bool"}, {"name": "payload", "type": "cell"}], "name": "transferToWallet", "outputs": []}, {"id": "0x67A0B95F", "inputs": [{"name": "amount", "type": "uint128"}, {"name": "sender", "type": "address"}, {"name": "remainingGasTo", "type": "address"}, {"name": "notify", "type": "bool"}, {"name": "payload", "type": "cell"}], "name": "acceptTransfer", "outputs": []}, {"id": "0x4384F298", "inputs": [{"name": "amount", "type": "uint128"}, {"name": "remainingGasTo", "type": "address"}, {"name": "notify", "type": "bool"}, {"name": "payload", "type": "cell"}], "name": "acceptMint", "outputs": []}, {"inputs": [{"name": "to", "type": "address"}], "name": "sendSurplusGas", "outputs": []}], "header": ["pubkey", "time", "expire"], "version": "2.2"}"#;
        let abi = ton_abi::Contract::load(abi).unwrap();

        let events = abi.events.values().cloned().collect::<Vec<_>>();
        let funs = abi.functions.values().cloned().collect::<Vec<_>>();

        let _parser = TransactionParser::builder()
            .function_in_list(funs.clone(), false)
            .functions_out_list(funs, false)
            .events_list(events)
            .build_with_external_in()
            .unwrap();
    }

    #[test]
    fn test_parse_events() {
        let tx = "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";
        let tx = Transaction::construct_from_base64(tx).unwrap();
        let abi = r#"{"ABI version":2,"version":"2.1","header":["time","expire"],"functions":[{"name":"constructor","inputs":[{"name":"_owner","type":"address"},{"name":"_meta","type":"cell"}],"outputs":[]},{"name":"setMeta","inputs":[{"name":"_meta","type":"cell"}],"outputs":[]},{"name":"setEndBlockNumber","inputs":[{"name":"endBlockNumber","type":"uint32"}],"outputs":[]},{"name":"deployEvent","inputs":[{"components":[{"name":"eventTransaction","type":"uint256"},{"name":"eventIndex","type":"uint32"},{"name":"eventData","type":"cell"},{"name":"eventBlockNumber","type":"uint32"},{"name":"eventBlock","type":"uint256"}],"name":"eventVoteData","type":"tuple"}],"outputs":[]},{"name":"deriveEventAddress","inputs":[{"name":"answerId","type":"uint32"},{"components":[{"name":"eventTransaction","type":"uint256"},{"name":"eventIndex","type":"uint32"},{"name":"eventData","type":"cell"},{"name":"eventBlockNumber","type":"uint32"},{"name":"eventBlock","type":"uint256"}],"name":"eventVoteData","type":"tuple"}],"outputs":[{"name":"eventContract","type":"address"}]},{"name":"getDetails","inputs":[{"name":"answerId","type":"uint32"}],"outputs":[{"components":[{"name":"eventABI","type":"bytes"},{"name":"staking","type":"address"},{"name":"eventInitialBalance","type":"uint64"},{"name":"eventCode","type":"cell"}],"name":"_basicConfiguration","type":"tuple"},{"components":[{"name":"chainId","type":"uint32"},{"name":"eventEmitter","type":"uint160"},{"name":"eventBlocksToConfirm","type":"uint16"},{"name":"proxy","type":"address"},{"name":"startBlockNumber","type":"uint32"},{"name":"endBlockNumber","type":"uint32"}],"name":"_networkConfiguration","type":"tuple"},{"name":"_meta","type":"cell"}]},{"name":"getType","inputs":[{"name":"answerId","type":"uint32"}],"outputs":[{"name":"_type","type":"uint8"}]},{"name":"broxusBridgeCallback","inputs":[{"components":[{"components":[{"name":"eventTransaction","type":"uint256"},{"name":"eventIndex","type":"uint32"},{"name":"eventData","type":"cell"},{"name":"eventBlockNumber","type":"uint32"},{"name":"eventBlock","type":"uint256"}],"name":"voteData","type":"tuple"},{"name":"configuration","type":"address"},{"name":"staking","type":"address"},{"name":"chainId","type":"uint32"}],"name":"eventInitData","type":"tuple"},{"name":"gasBackAddress","type":"address"}],"outputs":[]},{"name":"transferOwnership","inputs":[{"name":"newOwner","type":"address"}],"outputs":[]},{"name":"renounceOwnership","inputs":[],"outputs":[]},{"name":"owner","inputs":[],"outputs":[{"name":"owner","type":"address"}]},{"name":"basicConfiguration","inputs":[],"outputs":[{"components":[{"name":"eventABI","type":"bytes"},{"name":"staking","type":"address"},{"name":"eventInitialBalance","type":"uint64"},{"name":"eventCode","type":"cell"}],"name":"basicConfiguration","type":"tuple"}]},{"name":"networkConfiguration","inputs":[],"outputs":[{"components":[{"name":"chainId","type":"uint32"},{"name":"eventEmitter","type":"uint160"},{"name":"eventBlocksToConfirm","type":"uint16"},{"name":"proxy","type":"address"},{"name":"startBlockNumber","type":"uint32"},{"name":"endBlockNumber","type":"uint32"}],"name":"networkConfiguration","type":"tuple"}]},{"name":"meta","inputs":[],"outputs":[{"name":"meta","type":"cell"}]}],"data":[{"components":[{"name":"eventABI","type":"bytes"},{"name":"staking","type":"address"},{"name":"eventInitialBalance","type":"uint64"},{"name":"eventCode","type":"cell"}],"key":1,"name":"basicConfiguration","type":"tuple"},{"components":[{"name":"chainId","type":"uint32"},{"name":"eventEmitter","type":"uint160"},{"name":"eventBlocksToConfirm","type":"uint16"},{"name":"proxy","type":"address"},{"name":"startBlockNumber","type":"uint32"},{"name":"endBlockNumber","type":"uint32"}],"key":2,"name":"networkConfiguration","type":"tuple"}],"events":[{"name":"OwnershipTransferred","inputs":[{"name":"previousOwner","type":"address"},{"name":"newOwner","type":"address"}],"outputs":[]},{"name":"NewEventContract","inputs":[{"name":"eventContract","type":"address"}],"outputs":[]}],"fields":[{"name":"_pubkey","type":"uint256"},{"name":"_timestamp","type":"uint64"},{"name":"_constructorFlag","type":"bool"},{"name":"owner","type":"address"},{"components":[{"name":"eventABI","type":"bytes"},{"name":"staking","type":"address"},{"name":"eventInitialBalance","type":"uint64"},{"name":"eventCode","type":"cell"}],"name":"basicConfiguration","type":"tuple"},{"components":[{"name":"chainId","type":"uint32"},{"name":"eventEmitter","type":"uint160"},{"name":"eventBlocksToConfirm","type":"uint16"},{"name":"proxy","type":"address"},{"name":"startBlockNumber","type":"uint32"},{"name":"endBlockNumber","type":"uint32"}],"name":"networkConfiguration","type":"tuple"},{"name":"meta","type":"cell"}]}"#;

        let abi = ton_abi::Contract::load(abi).unwrap();

        let events = abi
            .events
            .values()
            .cloned()
            .inspect(|x| println!("{}:{}:{}", x.get_function_id(), x.get_id(), x.name))
            .collect::<Vec<_>>();
        let parser = TransactionParser::builder()
            .events_list(events)
            .build_with_external_in()
            .unwrap();
        let parsed = parser.parse(&tx).unwrap();
        assert!(!parsed.is_empty());
        assert_eq!(parsed.first().unwrap().name, "NewEventContract");
    }
}
