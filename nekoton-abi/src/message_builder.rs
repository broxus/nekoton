use anyhow::Result;
use dyn_clone::DynClone;
use serde::{Deserialize, Serialize};
use ton_abi::{Function, Token};
use ton_block::Serializable;

use nekoton_utils::*;

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

pub trait UnsignedMessage: DynClone + Send + Sync {
    /// Adjust expiration timestamp from now
    fn refresh_timeout(&mut self, clock: &dyn Clock);

    /// Current expiration timestamp
    fn expire_at(&self) -> u32;

    /// Message body hash
    fn hash(&self) -> &[u8];

    /// Create signed message from prepared inputs
    /// # Arguments
    /// `signature` - signature, received from [`hash`]
    fn sign(&self, signature: &[u8; 64]) -> Result<SignedMessage>;
}

dyn_clone::clone_trait_object!(UnsignedMessage);

#[derive(Clone, Debug)]
pub struct SignedMessage {
    pub message: ton_block::Message,
    pub expire_at: u32,
}

impl Serialize for SignedMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        use serde::ser::Error;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SignedMessageHelper {
            #[serde(with = "serde_uint256")]
            pub hash: ton_types::UInt256,
            pub expire_at: u32,
            #[serde(with = "serde_cell")]
            pub boc: ton_types::Cell,
        }

        let boc: ton_types::Cell = self
            .message
            .write_to_new_cell()
            .map_err(Error::custom)?
            .into();

        SignedMessageHelper {
            hash: boc.repr_hash(),
            expire_at: self.expire_at,
            boc,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SignedMessageHelper {
            pub expire_at: u32,
            #[serde(with = "serde_ton_block")]
            pub boc: ton_block::Message,
        }

        let SignedMessageHelper { expire_at, boc } =
            <SignedMessageHelper as Deserialize>::deserialize(deserializer)?;

        Ok(Self {
            message: boc,
            expire_at,
        })
    }
}
