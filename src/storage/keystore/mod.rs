use std::fmt;
use std::fmt::{Debug, Formatter};
use std::io::Read;
use std::num::NonZeroU32;

use anyhow::Result;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{ed25519, Keypair, SecretKey, Signer};
use ring::rand::SecureRandom;
use ring::{digest, pbkdf2};
use secstr::{SecStr, SecVec};
use serde::{Deserialize, Serialize};

use crate::storage::derive_from_words;

use super::AccountType;

pub mod mnemonics;

const NONCE_LENGTH: usize = 12;

const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

#[cfg(debug_assertions)]
const N_ITER: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(1) };

///Change it to tune number of iterations in pbkdf2 function. Higher number - password bruteforce becomes slower.
/// Initial value is optimal for the current machine, so you maybe want to change it.
#[cfg(not(debug_assertions))]
const N_ITER: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(100_000) };

// TODO: stored keys management

#[derive(Clone)]
pub struct StoredKey {
    inner: CryptoData,
}

impl StoredKey {
    /// Initializes signer from key pair
    pub fn new(password: SecStr, account_type: AccountType, phrase: &str) -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();
        // prepare nonce
        let mut private_key_nonce = [0u8; 12];
        rng.fill(&mut private_key_nonce)
            .map_err(KeystoreError::FailedToGenerateRandomBytes)?;
        let private_key_nonce = Nonce::clone_from_slice(&private_key_nonce);

        let mut seed_phrase_nonce = [0u8; 12];
        rng.fill(&mut seed_phrase_nonce)
            .map_err(KeystoreError::FailedToGenerateRandomBytes)?;
        let seed_phrase_nonce = Nonce::clone_from_slice(&seed_phrase_nonce);

        let mut salt = vec![0u8; CREDENTIAL_LEN];
        rng.fill(salt.as_mut_slice())
            .map_err(KeystoreError::FailedToGenerateRandomBytes)?;

        // prepare encryptor
        let key = symmetric_key_from_password(password, &salt);
        let encryptor = ChaCha20Poly1305::new(&key);

        let keypair = derive_from_words(&phrase, account_type)?;
        // encrypt private key
        let pubkey = keypair.public;
        let encrypted_private_key =
            encrypt(&encryptor, &private_key_nonce, keypair.secret.as_ref())?;

        drop(keypair);

        // encrypt seed phrase
        let encrypted_seed_phrase = encrypt(&encryptor, &seed_phrase_nonce, phrase.as_ref())?;

        Ok(Self {
            inner: CryptoData {
                salt,
                encrypted_private_key,
                private_key_nonce,
                account_type,
                encrypted_seed_phrase,
                seed_phrase_nonce,
                pubkey,
            },
        })
    }

    pub fn from_reader<T>(reader: T) -> Result<Self>
    where
        T: Read,
    {
        let crypto_data: CryptoData = serde_json::from_reader(reader)?;
        Ok(StoredKey { inner: crypto_data })
    }

    pub fn change_password(&mut self, old_password: SecStr, new_password: SecStr) -> Result<()> {
        let rng = ring::rand::SystemRandom::new();

        // prepare nonce
        let mut new_private_key_nonce = vec![0u8; 12];
        rng.fill(&mut new_private_key_nonce)
            .map_err(KeystoreError::FailedToGenerateRandomBytes)?;
        let new_private_key_nonce = Nonce::clone_from_slice(&new_private_key_nonce);

        let mut new_seed_phrase_nonce = [0u8; 12];
        rng.fill(&mut new_seed_phrase_nonce)
            .map_err(KeystoreError::FailedToGenerateRandomBytes)?;
        let new_seed_phrase_nonce = Nonce::clone_from_slice(&new_seed_phrase_nonce);

        let mut new_salt = vec![0u8; CREDENTIAL_LEN];
        rng.fill(&mut new_salt)
            .map_err(KeystoreError::FailedToGenerateRandomBytes)?;

        // prepare encryptor/decrypter pair
        let old_key = symmetric_key_from_password(old_password, &self.inner.salt);
        let new_key = symmetric_key_from_password(new_password, &new_salt);

        let decrypter = ChaCha20Poly1305::new(&old_key);
        let encryptor = ChaCha20Poly1305::new(&new_key);

        // reencrypt key pair
        let new_encrypted_private_key = {
            let key_pair = decrypt_key_pair(
                &self.inner.encrypted_private_key,
                &old_key,
                &self.inner.private_key_nonce,
            )?;
            encrypt(&encryptor, &new_private_key_nonce, key_pair.secret.as_ref())?
        };

        // reencrypt seed phrase
        let new_encrypted_seed_phrase = {
            let seed_phrase = decrypt_secure(
                &decrypter,
                &self.inner.seed_phrase_nonce,
                &self.inner.encrypted_seed_phrase,
            )?;
            encrypt(&encryptor, &new_seed_phrase_nonce, seed_phrase.unsecure())?
        };

        // save new data
        self.inner.salt = new_salt;

        self.inner.encrypted_private_key = new_encrypted_private_key;
        self.inner.private_key_nonce = new_private_key_nonce;

        self.inner.encrypted_seed_phrase = new_encrypted_seed_phrase;
        self.inner.seed_phrase_nonce = new_seed_phrase_nonce;

        // done
        Ok(())
    }

    pub fn sign(&self, data: &[u8], password: SecStr) -> Result<[u8; ed25519::SIGNATURE_LENGTH]> {
        self.inner.sign(data, password)
    }

    ///Used for gas estimation
    pub fn sign_with_fake_key(&self, data: &[u8]) -> [u8; ed25519::SIGNATURE_LENGTH] {
        let pk = SecretKey::from_bytes(&[0; 32]).expect("Shouldn't fail");
        let pubkey = ed25519_dalek::PublicKey::from(&pk);
        let kp = Keypair {
            public: pubkey,
            secret: pk,
        };
        kp.sign(data).to_bytes()
    }

    pub fn public_key(&self) -> &[u8; 32] {
        self.inner.pubkey.as_bytes()
    }

    pub fn as_json(&self) -> String {
        serde_json::to_string(&self.inner).expect("Shouldn't fail")
    }
}

//TODO: fake key

impl Debug for StoredKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.inner.pubkey)
    }
}

///Data, stored on disk in `encrypted_data` filed of config.
#[derive(Serialize, Deserialize, Clone)]
struct CryptoData {
    account_type: AccountType,

    #[serde(with = "hex_pubkey")]
    pubkey: ed25519_dalek::PublicKey,

    #[serde(with = "hex_encode")]
    encrypted_private_key: Vec<u8>,
    #[serde(with = "hex_nonce")]
    private_key_nonce: Nonce,

    #[serde(with = "hex_encode")]
    encrypted_seed_phrase: Vec<u8>,
    #[serde(with = "hex_nonce")]
    seed_phrase_nonce: Nonce,

    #[serde(with = "hex_encode")]
    salt: Vec<u8>,
}

impl CryptoData {
    pub fn sign(&self, data: &[u8], password: SecStr) -> Result<[u8; ed25519::SIGNATURE_LENGTH]> {
        let key = symmetric_key_from_password(password, &*self.salt);
        let decrypter = ChaCha20Poly1305::new(&key);

        let secret = decrypt_secure(
            &decrypter,
            &self.private_key_nonce,
            &self.encrypted_private_key,
        )
        .and_then(|x| {
            ed25519_dalek::SecretKey::from_bytes(x.unsecure())
                .map_err(|_| KeystoreError::InvalidPrivateKey)
        })?;

        let pair = Keypair {
            secret,
            public: self.pubkey,
        };
        Ok(pair.sign(&data).to_bytes())
    }
}

fn decrypt_key_pair(
    encrypted_key: &[u8],
    key: &Key,
    nonce: &Nonce,
) -> Result<ed25519_dalek::Keypair, KeystoreError> {
    let decrypter = ChaCha20Poly1305::new(&key);

    decrypt(&decrypter, nonce, encrypted_key).and_then(|data| {
        let secret = ed25519_dalek::SecretKey::from_bytes(&data)
            .map_err(|_| KeystoreError::InvalidPrivateKey)?;
        let public = ed25519_dalek::PublicKey::from(&secret);
        Ok(Keypair { secret, public })
    })
}

/// Decrypts data using specified decrypter and nonce
fn decrypt_secure(
    dec: &ChaCha20Poly1305,
    nonce: &Nonce,
    data: &[u8],
) -> Result<SecVec<u8>, KeystoreError> {
    decrypt(dec, nonce, data).map(SecVec::new)
}

/// Decrypts data using specified decrypter and nonce
fn decrypt(dec: &ChaCha20Poly1305, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    dec.decrypt(nonce, data)
        .map_err(|_| KeystoreError::FailedToDecryptData)
}

/// Encrypts data using specified encryptor and nonce
fn encrypt(enc: &ChaCha20Poly1305, nonce: &Nonce, data: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    enc.encrypt(nonce, data)
        .map_err(|_| KeystoreError::FailedToEncryptData)
}

/// Calculates symmetric key from user password, using pbkdf2
fn symmetric_key_from_password(password: SecStr, salt: &[u8]) -> Key {
    let mut pbkdf2_hash = SecVec::new(vec![0; CREDENTIAL_LEN]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        N_ITER,
        salt,
        password.unsecure(),
        &mut pbkdf2_hash.unsecure_mut(),
    );
    chacha20poly1305::Key::clone_from_slice(&pbkdf2_hash.unsecure())
}

#[derive(thiserror::Error, Debug)]
pub enum KeystoreError {
    #[error("Failed to generate random bytes")]
    FailedToGenerateRandomBytes(ring::error::Unspecified),
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Failed to decrypt data")]
    FailedToDecryptData,
    #[error("Failed to encrypt data")]
    FailedToEncryptData,
}

mod hex_encode {
    use serde::Deserialize;

    pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]> + Sized,
        S: serde::Serializer,
    {
        serializer.serialize_str(&*hex::encode(&data.as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        <String as serde::Deserialize>::deserialize(deserializer)
            .and_then(|string| hex::decode(string).map_err(|e| D::Error::custom(e.to_string())))
    }
}

mod hex_pubkey {
    use ed25519_dalek::PublicKey;

    use super::hex_encode;

    pub fn serialize<S>(data: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&*hex::encode(&data.as_ref()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        hex_encode::deserialize(deserializer).and_then(|x| {
            PublicKey::from_bytes(x.as_slice()).map_err(|e| D::Error::custom(e.to_string()))
        })
    }
}

mod hex_nonce {
    use chacha20poly1305::Nonce;

    use super::*;

    pub fn serialize<S>(data: &Nonce, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        hex_encode::serialize(data, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Nonce, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        hex_encode::deserialize(deserializer).and_then(|x| {
            if x.len() != NONCE_LENGTH {
                Err(serde::de::Error::custom(format!(
                    "Bad nonce len: {}, expected: 12",
                    x.len()
                )))
            } else {
                Ok(Nonce::clone_from_slice(&*x))
            }
        })
    }
}

#[cfg(test)]
mod test {
    // use secstr::SecStr;
    // use crate::storage::{StoredKey, AccountType};
    //
    // fn default_keys() -> ed25519_dalek::Keypair {
    //     let ton_private_key = ed25519_dalek::SecretKey::from_bytes(
    //         &hex::decode("e371ef1d7266fc47b30d49dc886861598f09e2e6294d7f0520fe9aa460114e51")
    //             .unwrap(),
    //     )
    //     .unwrap();
    //     let ton_public_key = ed25519_dalek::PublicKey::from(&ton_private_key);
    //     let ton_key_pair = ed25519_dalek::Keypair {
    //         secret: ton_private_key,
    //         public: ton_public_key,
    //     };
    //
    //     ton_key_pair
    // }
    //
    // #[test]
    // fn test_init() {
    //     let password = SecStr::new("123".into());
    //
    //     let ton_key_pair = default_keys();
    //
    //     let (signer, data) = StoredKey::new(password.clone(), AccountType::Legacy, ).unwrap();
    //     let read_signer = TonSigner::from_reader(data.as_bytes(), password).unwrap();
    //
    //     assert_eq!(read_signer, signer);
    // }
    //
    // #[test]
    // fn test_bad_password() {
    //     let password = SecStr::new("123".into());
    //
    //     let ton_key_pair = default_keys();
    //
    //     let (_, data) = TonSigner::init(password, ton_key_pair).unwrap();
    //     let result = TonSigner ::from_reader(data.as_bytes(), SecStr::new("lol".into()));
    //     assert!(result.is_err());
    // }
}
