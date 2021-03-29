use super::Result;
use crate::utils::NoFailure;
use ton_abi::{Function, Token};
use ton_block::{CommonMsgInfo, Deserializable, Message, Transaction, TransactionId};
use ton_types::UInt256;

pub struct AbiParser<'a> {
    params: MessageProcessingParams<'a>,
}

pub struct MessageProcessingParams<'a> {
    pub event_transaction: &'a UInt256,
    pub event_transaction_lt: u64,
    pub event_timestamp: u32,
    pub abi_function: Option<&'a Function>,
}

#[derive(Debug, Clone, Default)]
pub struct ContractOutput {
    pub transaction_id: Option<TransactionId>,
    pub tokens: Vec<Token>,
}

pub fn process_out_messages<'a>(
    messages: &'a [Message],
    params: &MessageProcessingParams<'a>,
) -> Result<ContractOutput> {
    let mut output = None;

    for msg in messages {
        if !matches!(msg.header(), CommonMsgInfo::ExtOutMsgInfo(_)) {
            continue;
        }

        let body = msg
            .body()
            .ok_or_else(|| anyhow::anyhow!("output message has not body"))?;

        match &params.abi_function {
            Some(abi_function)
                if output.is_none()
                    && abi_function
                        .is_my_output_message(body.clone(), false)
                        .convert()? =>
            {
                let tokens = abi_function.decode_output(body, false).convert()?;

                output = Some(ContractOutput {
                    transaction_id: None,
                    tokens,
                });
            }
            _ => (),
        }
    }

    match (params.abi_function, output) {
        (Some(abi_function), _) if !abi_function.has_output() => Ok(Default::default()),
        (Some(_), Some(output)) => Ok(output),
        (None, _) => Ok(Default::default()),
        _ => anyhow::bail!("no external output messages"),
    }
}

fn parse_transaction_messages(transaction: &Transaction) -> Result<Vec<Message>> {
    let mut messages = Vec::new();
    transaction
        .out_msgs
        .iterate_slices(|slice| {
            if let Ok(message) = slice.reference(0).and_then(Message::construct_from_cell) {
                messages.push(message);
            }
            Ok(true)
        })
        .convert()?;
    Ok(messages)
}

impl<'a> AbiParser<'a> {
    pub fn new(params: MessageProcessingParams<'a>) -> Result<Self> {
        Ok(Self { params })
    }

    pub fn parse(&self, tx: &Transaction) -> Result<ContractOutput> {
        let messages = parse_transaction_messages(&tx)?;
        process_out_messages(&*messages, &self.params)
    }
}
