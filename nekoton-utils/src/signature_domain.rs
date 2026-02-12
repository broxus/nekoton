use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct ToSign {
    pub ctx: SignatureContext,
    pub data: Vec<u8>,
}

impl ToSign {
    pub fn write_to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();

        match (self.ctx.signature_type, self.ctx.global_id) {
            (SignatureType::SignatureDomain, Some(global_id)) => {
                let sd = SignatureDomain::L2 { global_id };
                output.extend_from_slice(&sd.hash())
            }
            (SignatureType::SignatureId, Some(global_id)) => {
                output.extend_from_slice(&global_id.to_be_bytes())
            }
            _ => {}
        }

        output.extend_from_slice(&self.data);

        output
    }
}

#[derive(Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct SignatureContext {
    pub global_id: Option<i32>,
    pub signature_type: SignatureType,
}

#[derive(Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum SignatureType {
    Empty,
    SignatureId,
    #[default]
    SignatureDomain,
}

impl SignatureContext {
    pub fn sign<'a>(
        &self,
        key: &ed25519_dalek::Keypair,
        data: &'a [u8],
    ) -> ed25519_dalek::Signature {
        let data = match self.signature_type {
            SignatureType::Empty => Cow::Borrowed(data),
            SignatureType::SignatureId => extend_with_signature_id(data, self.global_id),
            SignatureType::SignatureDomain => extend_with_signature_domain(data, self.global_id),
        };

        key.sign(&data)
    }
}

/// Signature domain variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureDomain {
    /// Special variant to NOT add any prefix for the verified data.
    /// Can be used to verify mainnet signatures from L2 networks.
    Empty,
    /// Non-empty variant. Hash of its TL representation
    /// is used as a prefix for the verified data.
    L2 {
        /// Global id of the network.
        global_id: i32,
    },
}

impl SignatureDomain {
    /// Prepares arbitrary data for signing.
    fn apply<'a>(&self, data: &'a [u8]) -> Cow<'a, [u8]> {
        if let Self::Empty = self {
            Cow::Borrowed(data)
        } else {
            let hash = self.hash();
            let mut result = Vec::with_capacity(32 + data.len());
            result.extend_from_slice(&hash);
            result.extend_from_slice(data);
            Cow::Owned(result)
        }
    }

    fn hash(&self) -> Vec<u8> {
        Sha256::digest(self.write_to_bytes()).to_vec()
    }

    fn write_to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        match self {
            Self::Empty => {
                data.extend_from_slice(&0xe1d571bu32.to_le_bytes()); //Empty variant tl tag
            }
            Self::L2 { global_id } => {
                data.extend_from_slice(&0x71b34ee1u32.to_le_bytes()); // L2 variant tl tag
                data.extend_from_slice(&global_id.to_le_bytes());
            }
        }

        data
    }
}

fn extend_with_signature_id(data: &[u8], global_id: Option<i32>) -> Cow<'_, [u8]> {
    match global_id {
        Some(signature_id) => {
            let mut extended_data = Vec::with_capacity(4 + data.len());
            extended_data.extend_from_slice(&signature_id.to_be_bytes());
            extended_data.extend_from_slice(data);
            Cow::Owned(extended_data)
        }
        None => Cow::Borrowed(data),
    }
}

fn extend_with_signature_domain(data: &[u8], global_id: Option<i32>) -> Cow<'_, [u8]> {
    let sd = match global_id {
        None => SignatureDomain::Empty,
        Some(global_id) => SignatureDomain::L2 { global_id },
    };
    sd.apply(data)
}
