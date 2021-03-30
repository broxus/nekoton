use super::Result;
use crate::utils::NoFailure;
use ton_abi::{Function, Token};
use ton_block::{CommonMsgInfo, Deserializable, Message, Transaction, TransactionId};
use ton_types::UInt256;

pub struct AbiParser {
    fun: Function,
}

#[derive(Debug, Clone, Default)]
pub struct ContractOutput {
    pub transaction_id: Option<TransactionId>,
    pub tokens: Vec<Token>,
}

pub fn process_out_messages(
    messages: &[Message],
    abi_function: &Function,
) -> Result<ContractOutput> {
    let mut output = None;

    for msg in messages {
        if !matches!(msg.header(), CommonMsgInfo::ExtOutMsgInfo(_)) {
            continue;
        }

        let body = msg
            .body()
            .ok_or_else(|| anyhow::anyhow!("output message has not body"))?;
        let tokens = abi_function.decode_output(body, false).convert()?;

        output = Some(ContractOutput {
            transaction_id: None,
            tokens,
        });
    }

    match output {
        Some(a) => Ok(a),
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

impl AbiParser {
    pub fn new(fun: Function) -> Result<Self> {
        Ok(Self { fun })
    }

    pub fn parse(&self, tx: &Transaction) -> Result<ContractOutput> {
        let messages = parse_transaction_messages(&tx)?;
        process_out_messages(&*messages, &self.fun)
    }
}
#[cfg(test)]
mod test {
    use crate::contracts::execution::abi::AbiParser;
    use crate::contracts::execution::compiled::CompiledContract;
    use crate::utils::TrustMe;
    use ton_block::{Deserializable, Message, Transaction};
    use ton_executor::BlockchainConfig;
    use ton_types::Cell;
    #[test]
    fn test() {
        let contract = r#####"{
	"ABI version": 2,
	"header": ["pubkey", "time", "expire"],
	"functions": [
		{
			"name": "getCustodians",
			"inputs": [
			],
			"outputs": [
				{"components":[{"name":"index","type":"uint8"},{"name":"pubkey","type":"uint256"}],"name":"custodians","type":"tuple[]"}
			]
		}
	],
	"data": [
	],
	"events": [
	]
}"#####;
        let contract_abi = ton_abi::Contract::load(&mut std::io::Cursor::new(contract)).trust_me();
        let function = contract_abi.function("getCustodians").trust_me();
        dbg!(&function);
        // let contract_code = base64::decode("te6ccgECDwEAArcAA7dxjJmv/+E9MIE3D3fBD8TVG8VOUrjhgdtqDou3VFbZH/AAALPVJCfkGksT3Y8aHAm7mnKfGA/AccQcwRmJeHov8yXElkW09QQwAACz0BBMOBYGHORAAFSAICXTqAUEAQIRDINHRh4pg8RAAwIAb8mPQkBMUWFAAAAAAAAEAAAAAAAEDt5ElKCY0ANTjCaw8ltpBJRSPdcEmknKxwOoduRmHbJAkCSUAJ1GT2MTiAAAAAAAAAAAWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAIJy3y4B4TEhaY3M9HQMWqBpVJc3IUvntA5EtNHkjN1t4sqjUitqEc3Fb6TafRVFXMJNDjglljNUbcLzalj6ghNYgAIB4AsGAgHdCQcBASAIAHXgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/4AAAWeqSE/IbAw5yISY7BZoAAAAAAAAAAQAEBIAoAsUgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/8ABjJmv/+E9MIE3D3fBD8TVG8VOUrjhgdtqDou3VFbZH/QdzWUAAYUWGAAABZ6pIT8hMDDnIhAAUWIADGTNf/8J6YQJuHu+CH4mqN4qcpXHDA7bUHRduqK2yP+DAwB4ZDdhiTVlESmgip5GbEUIYUaZ+kx7vy+VFW60Kn7S031EE++HJh4nu39RuoM4HIWy7cjLSwAA3RIMne+L/YQA4D8drjTwv63I+aPTBLtMULU+zuEMSAmO8j5A00qizUXzUAAAF4fg2s9P////8THYLNgDQFjgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/4AAAAAAAAAAAAAAAA7msoAQOAAA=").unwrap();
        let msg_code = base64::decode("").unwrap();
        // let contract = CompiledContract::new(
        //     Cell::construct_from_bytes(&contract_code).unwrap(),
        //     BlockchainConfig::default(),
        //     12358001000001,
        //     12356916000000,
        // );
        let tx = Transaction::construct_from_base64("te6ccgECDwEAArcAA7dxjJmv/+E9MIE3D3fBD8TVG8VOUrjhgdtqDou3VFbZH/AAALPVJCfkGksT3Y8aHAm7mnKfGA/AccQcwRmJeHov8yXElkW09QQwAACz0BBMOBYGHORAAFSAICXTqAUEAQIRDINHRh4pg8RAAwIAb8mPQkBMUWFAAAAAAAAEAAAAAAAEDt5ElKCY0ANTjCaw8ltpBJRSPdcEmknKxwOoduRmHbJAkCSUAJ1GT2MTiAAAAAAAAAAAWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAIJy3y4B4TEhaY3M9HQMWqBpVJc3IUvntA5EtNHkjN1t4sqjUitqEc3Fb6TafRVFXMJNDjglljNUbcLzalj6ghNYgAIB4AsGAgHdCQcBASAIAHXgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/4AAAWeqSE/IbAw5yISY7BZoAAAAAAAAAAQAEBIAoAsUgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/8ABjJmv/+E9MIE3D3fBD8TVG8VOUrjhgdtqDou3VFbZH/QdzWUAAYUWGAAABZ6pIT8hMDDnIhAAUWIADGTNf/8J6YQJuHu+CH4mqN4qcpXHDA7bUHRduqK2yP+DAwB4ZDdhiTVlESmgip5GbEUIYUaZ+kx7vy+VFW60Kn7S031EE++HJh4nu39RuoM4HIWy7cjLSwAA3RIMne+L/YQA4D8drjTwv63I+aPTBLtMULU+zuEMSAmO8j5A00qizUXzUAAAF4fg2s9P////8THYLNgDQFjgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/4AAAAAAAAAAAAAAAA7msoAQOAAA=").trust_me();
        let parser = AbiParser::new(function.clone()).trust_me();
        dbg!(parser.parse(&tx).unwrap());
    }
}
