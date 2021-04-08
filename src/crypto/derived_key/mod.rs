use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{PublicKey, Signer};
use secstr::{SecStr, SecVec};
use thiserror::Error;
use tiny_hderive::bip44::IntoDerivationPath;
use zeroize::Zeroize;

use crate::storage::{Signer as StorSigner, SignerEntry, SignerStorage, WithPublicKey};

pub type AccountMap = HashMap<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH], u32>;

#[derive(Clone)]
struct MasterKey {
    enc_entropy: Vec<u8>,
    mnmemonic: Vec<u8>,
    entropy_nonce: Nonce,
    mnemonic_nonce: Nonce,
    salt: [u8; 12],
    acc_map: AccountMap,
    entries: Vec<SignerEntry>,
}
// # Storage related stuff
//
// KeyStore example:
// ```no_run
// struct MySigner;
// impl Signer for MySigner { ... }
//
// struct AnotherSigner;
// impl Signer for AnotherSigner { ... }
//
// fn create_keystore(storage: Arc<dyn Storage>) -> Result<KeyStore> {
//     KeyStore::new(storage)
//         .with_signer("simple_signer", MySigner)?
//         .with_signer("another_signer", AnotherSigner)?
//         .load()
//         .await
// }
//

#[async_trait]
impl SignerStorage for MasterKey {
    fn load_state(&mut self, data: &str) -> Result<()> {
        todo!()
    }

    fn store_state(&self) -> String {
        todo!()
    }

    fn get_entries(&self) -> Vec<SignerEntry> {
        self.entries.clone()
    }

    async fn remove_key(&mut self, public_key: &PublicKey) -> bool {
        let map = &mut self.acc_map;
        map.remove(public_key.as_bytes()).is_some()
    }

    async fn clear(&mut self) {
        let map = &mut self.acc_map;
        map.clear()
    }
}

struct MasterKeySignParams {
    account_id: u32,
    password: SecStr,
}

#[async_trait]
impl StorSigner for MasterKey {
    type CreateKeyInput = MasterKey;
    type SignInput = MasterKeySignParams;

    async fn add_key(&mut self, name: &str, input: Self::CreateKeyInput) -> Result<PublicKey> {}

    async fn sign(&self, data: &[u8], input: Self::SignInput) -> Result<[u8; 64]> {
        let decryptor = ChaCha20Poly1305::new(&super::symmetric::symmetric_key_from_password(
            input.password,
            &self.salt,
        ));

        let master = decrypt_secure(&decryptor, &self.entropy_nonce, &*self.enc_entropy)?;
        let signer = derive_from_master(input.account_id, master)?;
        Ok(signer.sign(data).to_bytes())
    }
}

fn derive_from_master(id: u32, master: SecVec<u8>) -> Result<ed25519_dalek::Keypair> {
    use tiny_hderive::bip32;

    let path = format!("m/44'/396'/0'/0/{}", id).as_str();
    let key = bip32::ExtendedPrivKey::derive(master.unsecure(), path.into())
        .map_err(|_| MasterKeyError::DerivationError)?
        .secret();
    drop(master);
    let secret =
        ed25519_dalek::SecretKey::from_bytes(&key).map_err(|_| MasterKeyError::DerivationError)?;
    let public = ed25519_dalek::PublicKey::from(&secret);
    Ok(ed25519_dalek::Keypair { secret, public })
}

#[derive(Debug, Error)]
enum MasterKeyError {
    DerivationError,
    FailedToEncryptData,
    FailedToDecryptData,
}

/// Decrypts data using specified decrypter and nonce
fn decrypt_secure(
    dec: &ChaCha20Poly1305,
    nonce: &Nonce,
    data: &[u8],
) -> Result<SecVec<u8>, MasterKeyError> {
    decrypt(dec, nonce, data).map(SecVec::new)
}

/// Decrypts data using specified decrypter and nonce
fn decrypt(dec: &ChaCha20Poly1305, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>, MasterKeyError> {
    dec.decrypt(nonce, data)
        .map_err(|_| MasterKeyError::FailedToDecryptData)
}

/// Encrypts data using specified encryptor and nonce
fn encrypt(enc: &ChaCha20Poly1305, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>, MasterKeyError> {
    enc.encrypt(nonce, data)
        .map_err(|_| MasterKeyError::FailedToEncryptData)
}
