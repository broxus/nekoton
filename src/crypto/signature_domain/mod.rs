use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use std::borrow::Cow;

pub struct ToSign {
    pub enable_signature_domains: bool,
    pub signature_domain: SignatureDomain,
    pub data: Vec<u8>,
}

impl ToSign {
    pub fn write_to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();

        match self.signature_domain {
            // Empty signature domain always doesn't have any prefix.
            SignatureDomain::Empty => {}
            // All other signature domains are prefixed as hash.
            _ if self.enable_signature_domains => {
                output.extend_from_slice(&self.signature_domain.get_tl_hash());
            }
            // Fallback for the original `SignatureWithId` implementation
            // if domains are disabled.
            SignatureDomain::L2 { global_id } => output.extend_from_slice(&global_id.to_be_bytes()),
        }

        output.extend_from_slice(&self.data);

        output
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
    /// Signs arbitrary data using the key and optional signature id.
    pub fn sign(&self, key: &ed25519_dalek::Keypair, data: &[u8]) -> ed25519_dalek::Signature {
        let data = self.apply(data);
        key.sign(&data)
    }
    /// Prepares arbitrary data for signing.
    pub fn apply<'a>(&self, data: &'a [u8]) -> Cow<'a, [u8]> {
        if let Self::Empty = self {
            Cow::Borrowed(data)
        } else {
            let hash = self.get_tl_hash();
            let mut result = Vec::with_capacity(32 + data.len());
            result.extend_from_slice(&hash);
            result.extend_from_slice(data);
            Cow::Owned(result)
        }
    }

    fn get_tl_hash(&self) -> Vec<u8> {
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
