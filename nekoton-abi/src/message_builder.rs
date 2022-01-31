use ton_abi::{Function, Token};

use super::{BuildTokenValue, PackAbiPlain};

#[derive(Debug)]
pub struct MessageBuilder<'a> {
    function: &'a Function,
    inputs: Vec<Token>,
}

impl<'a> MessageBuilder<'a> {
    pub fn new(function: &'a ton_abi::Function) -> Self {
        let input = Vec::with_capacity(function.inputs.len());
        Self {
            function,
            inputs: input,
        }
    }

    pub fn arg<A>(mut self, value: A) -> Self
    where
        A: BuildTokenValue,
    {
        let name = &self.function.inputs[self.inputs.len()].name;
        self.inputs.push(Token::new(name, value.token_value()));
        self
    }

    pub fn args<A>(mut self, values: A) -> Self
    where
        A: PackAbiPlain,
    {
        self.inputs.extend(values.pack());
        self
    }

    pub fn build(self) -> (&'a Function, Vec<Token>) {
        (self.function, self.inputs)
    }
}
