use ton_abi::{Event, Param, ParamType};

#[derive(Default, Debug, Clone)]
pub struct EventBuilder {
    /// Contract function specification.
    /// ABI version
    abi_version: u8,
    /// Event name.
    name: String,
    /// Function input.
    inputs: Vec<Param>,
    /// Event ID
    event_id: u32,
}

impl EventBuilder {
    pub fn new(event_name: &str) -> Self {
        Self {
            name: event_name.to_string(),
            abi_version: 2,
            ..Default::default()
        }
    }

    pub fn in_arg(mut self, name: &str, arg_type: ParamType) -> Self {
        self.inputs.push(Param::new(name, arg_type));
        self
    }

    pub fn inputs(mut self, inputs: Vec<Param>) -> Self {
        self.inputs = inputs;
        self
    }

    pub fn build(self) -> Event {
        let mut event = Event {
            abi_version: self.abi_version,
            name: self.name,
            inputs: self.inputs,
            id: 0,
        };
        let id = event.get_function_id();
        event.id = id & 0x7FFFFFFF;
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ton_abi::ParamType;

    #[test]
    fn build() {
        let original = &nekoton_contracts::abi::safe_multisig_wallet().events()["TransferAccepted"];
        let imposter = EventBuilder::new("TransferAccepted")
            .in_arg("payload", ParamType::Bytes)
            .build();
        assert_eq!(original, &imposter)
    }
}
