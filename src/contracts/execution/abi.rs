use ton_abi::{Function, Token};
use ton_block::{
    CommonMsgInfo, Deserializable, ExternalInboundMessageHeader, Message, MsgAddressInt,
    Transaction,
};

use crate::utils::NoFailure;

use super::{match_contract_state, Result};

use crate::transport::models::ContractState;
use std::collections::HashMap;

use ton_executor::{BlockchainConfig, OrdinaryTransactionExecutor, TransactionExecutor};

pub struct FunctionAbi<'a> {
    fun: &'a Function,
}

impl<'a> FunctionAbi<'a> {
    pub fn new(fun: &'a Function) -> Result<Self> {
        Ok(Self { fun })
    }

    pub fn parse(&self, tx: &Transaction) -> Result<Vec<Token>> {
        let messages = parse_transaction_messages(&tx)?;
        process_out_messages(&*messages, &self.fun)
    }

    pub fn run_local(
        &self,
        address: MsgAddressInt,
        account_state: &ContractState,
        config: BlockchainConfig,
        input: &[Token],
    ) -> Result<Vec<Token>> {
        let executor = OrdinaryTransactionExecutor::new(config);
        let msg_body = self
            .fun
            .encode_input(&HashMap::default(), &input, false, None)
            .convert()?;
        let mut msg = Message::with_ext_in_header(ExternalInboundMessageHeader {
            src: Default::default(),
            dst: address,
            import_fee: Default::default(),
        });
        msg.set_body(msg_body.into());
        let (mut account, block_unix_time, block_lt, last_tx_lt) =
            match_contract_state(&account_state);
        let tx = executor
            .execute_for_account(
                Some(&msg),
                &mut account,
                Default::default(),
                block_unix_time,
                block_lt,
                last_tx_lt,
                false,
            )
            .convert()?;
        self.parse(&tx)
    }
}

fn process_out_messages(messages: &[Message], abi_function: &Function) -> Result<Vec<Token>> {
    let mut output = None;

    for msg in messages {
        dbg!(msg);
        if !matches!(msg.header(), CommonMsgInfo::ExtOutMsgInfo(_)) {
            continue;
        }

        let body = msg
            .body()
            .ok_or_else(|| anyhow::anyhow!("output message has not body"))?;

        if abi_function
            .is_my_output_message(body.clone(), false)
            .convert()?
        {
            let tokens = abi_function.decode_output(body, false).convert()?;

            output = Some(tokens);
            break;
        }
    }

    match output {
        Some(a) => Ok(a),
        None if !abi_function.has_output() => Ok(Default::default()),
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

#[cfg(test)]
mod test {
    use ton_block::{Deserializable, Transaction};

    use crate::contracts::execution::abi::FunctionAbi;

    use crate::utils::TrustMe;

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
		},
		{"name": "submitTransaction",
			"inputs": [
				{"name":"dest","type":"address"},
				{"name":"value","type":"uint128"},
				{"name":"bounce","type":"bool"},
				{"name":"allBalance","type":"bool"},
				{"name":"payload","type":"cell"}
			],
			"outputs": [
				{"name":"transId","type":"uint64"}
			]}
	],
	"data": [
	],
	"events": [
	]
}"#####;
        let contract_abi = ton_abi::Contract::load(&mut std::io::Cursor::new(contract)).trust_me();
        let function = contract_abi.function("submitTransaction").trust_me();
        dbg!(&function);
        let _msg_code = base64::decode("te6ccgEBBAEA0QABRYgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/4MAQHhkN2GJNWURKaCKnkZsRQhhRpn6THu/L5UVbrQqftLTfUQT74cmHie7f1G6gzgchbLtyMtLAADdEgyd74v9hADgPx2uNPC/rcj5o9MEu0xQtT7O4QxICY7yPkDTSqLNRfNQAAAXh+Daz0/////xMdgs2ACAWOAAxkzX//CemECbh7vgh+JqjeKnKVxwwO21B0Xbqitsj/gAAAAAAAAAAAAAAADuaygBAMAAA==").unwrap();
        let tx = Transaction::construct_from_base64("te6ccgECDwEAArcAA7dxjJmv/+E9MIE3D3fBD8TVG8VOUrjhgdtqDou3VFbZH/AAALPVJCfkGksT3Y8aHAm7mnKfGA/AccQcwRmJeHov8yXElkW09QQwAACz0BBMOBYGHORAAFSAICXTqAUEAQIRDINHRh4pg8RAAwIAb8mPQkBMUWFAAAAAAAAEAAAAAAAEDt5ElKCY0ANTjCaw8ltpBJRSPdcEmknKxwOoduRmHbJAkCSUAJ1GT2MTiAAAAAAAAAAAWAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAIJy3y4B4TEhaY3M9HQMWqBpVJc3IUvntA5EtNHkjN1t4sqjUitqEc3Fb6TafRVFXMJNDjglljNUbcLzalj6ghNYgAIB4AsGAgHdCQcBASAIAHXgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/4AAAWeqSE/IbAw5yISY7BZoAAAAAAAAAAQAEBIAoAsUgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/8ABjJmv/+E9MIE3D3fBD8TVG8VOUrjhgdtqDou3VFbZH/QdzWUAAYUWGAAABZ6pIT8hMDDnIhAAUWIADGTNf/8J6YQJuHu+CH4mqN4qcpXHDA7bUHRduqK2yP+DAwB4ZDdhiTVlESmgip5GbEUIYUaZ+kx7vy+VFW60Kn7S031EE++HJh4nu39RuoM4HIWy7cjLSwAA3RIMne+L/YQA4D8drjTwv63I+aPTBLtMULU+zuEMSAmO8j5A00qizUXzUAAAF4fg2s9P////8THYLNgDQFjgAMZM1//wnphAm4e74Ifiao3ipylccMDttQdF26orbI/4AAAAAAAAAAAAAAAA7msoAQOAAA=").trust_me();
        let parser = FunctionAbi::new(function).trust_me();
        dbg!(parser.parse(&tx).unwrap());
    }
}
