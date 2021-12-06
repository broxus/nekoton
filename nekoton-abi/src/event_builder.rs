use ton_abi::contract::{AbiVersion, ABI_VERSION_2_0};
use ton_abi::{Event, Param, ParamType};

#[derive(Debug, Clone)]
pub struct EventBuilder {
    /// Contract function specification.
    /// ABI version
    abi_version: AbiVersion,
    /// Event name.
    name: String,
    /// Function input.
    inputs: Vec<Param>,
}

impl EventBuilder {
    pub fn new(event_name: &str) -> Self {
        Self {
            name: event_name.to_string(),
            abi_version: ABI_VERSION_2_0,
            inputs: Vec::new(),
        }
    }

    pub fn abi_version(mut self, abi_version: AbiVersion) -> Self {
        self.abi_version = abi_version;
        self
    }

    /// Adds input param
    #[deprecated(note = "use `input` instead")]
    pub fn in_arg(self, name: &str, ty: ParamType) -> Self {
        self.input(name, ty)
    }

    /// Adds input param
    pub fn input(mut self, name: &str, ty: ParamType) -> Self {
        self.inputs.push(Param::new(name, ty));
        self
    }

    /// Sets the input params to the specified
    ///
    /// NOTE: Replaces previously added inputs
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
            .input("payload", ParamType::Bytes)
            .build();
        assert_eq!(original, &imposter)
    }
}
