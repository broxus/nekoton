use std::collections::hash_map::{self, HashMap};
use std::convert::TryInto;
use std::io::Read;

use anyhow::Result;
use async_trait::async_trait;
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{ed25519, Keypair, PublicKey, SecretKey, Signer};
use ring::digest;
use ring::rand::SecureRandom;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

use crate::crypto::{Signer as StoreSigner, SignerEntry, SignerStorage};
use crate::utils::*;

use super::mnemonic::*;
use super::symmetric::*;

#[derive(Default, Clone, Debug)]
pub struct EncryptedKeySigner {
    keys: KeysMap,
}

type KeysMap = HashMap<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH], EncryptedKey>;

impl EncryptedKeySigner {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_key(&self, public_key: &PublicKey) -> Result<&EncryptedKey> {
        match self.keys.get(public_key.as_bytes()) {
            Some(key) => Ok(key),
            None => Err(EncryptedKeyError::KeyNotFound.into()),
        }
    }

    fn get_key_mut(&mut self, public_key: &PublicKey) -> Result<&mut EncryptedKey> {
        match self.keys.get_mut(public_key.as_bytes()) {
            Some(key) => Ok(key),
            None => Err(EncryptedKeyError::KeyNotFound.into()),
        }
    }
}

#[async_trait]
impl StoreSigner for EncryptedKeySigner {
    type CreateKeyInput = EncryptedKeyCreateInput;
    type ExportKeyInput = EncryptedKeyPassword;
    type ExportKeyOutput = EncryptedKeyExportOutput;
    type UpdateKeyInput = EncryptedKeyUpdateParams;
    type SignInput = EncryptedKeyPassword;

    async fn add_key(&mut self, input: Self::CreateKeyInput) -> Result<SignerEntry> {
        let key = EncryptedKey::new(input.password, input.mnemonic_type, input.phrase)?;

        let public_key = *key.public_key();

        match self.keys.entry(public_key.to_bytes()) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(key);
                Ok(SignerEntry {
                    public_key,
                    account_id: input.mnemonic_type.account_id(),
                })
            }
            hash_map::Entry::Occupied(_) => return Err(EncryptedKeyError::KeyAlreadyExists.into()),
        }
    }

    async fn update_key(&mut self, input: Self::UpdateKeyInput) -> Result<SignerEntry> {
        let key = self.get_key_mut(&input.public_key)?;
        key.change_password(input.old_password, input.new_password)?;
        Ok(SignerEntry {
            public_key: input.public_key,
            account_id: key.mnemonic_type().account_id(),
        })
    }

    async fn export_key(&self, input: Self::ExportKeyInput) -> Result<Self::ExportKeyOutput> {
        let key = self.get_key(&input.public_key)?;
        Ok(Self::ExportKeyOutput {
            phrase: key.get_mnemonic(input.password)?,
            mnemonic_type: key.mnemonic_type(),
        })
    }

    async fn sign(&self, data: &[u8], input: Self::SignInput) -> Result<[u8; 64]> {
        let key = self.get_key(&input.public_key)?;
        key.sign(data, input.password)
    }
}

#[async_trait]
impl SignerStorage for EncryptedKeySigner {
    fn load_state(&mut self, data: &str) -> Result<()> {
        let data = serde_json::from_str::<Vec<(String, String)>>(data)?;

        self.keys = data
            .into_iter()
            .map(|(public_key, data)| {
                let public_key = hex::decode(&public_key)?
                    .try_into()
                    .map_err(|_| EncryptedKeyError::InvalidPublicKey)?;
                let data = EncryptedKey::from_reader(&mut std::io::Cursor::new(data))?;
                Ok((public_key, data))
            })
            .collect::<Result<_>>()?;

        Ok(())
    }

    fn store_state(&self) -> String {
        use serde::ser::SerializeSeq;

        struct StoredData<'a>(&'a KeysMap);
        #[derive(Serialize)]
        struct StoredDataItem<'a>(&'a str, &'a str);

        impl<'a> Serialize for StoredData<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                for (public_key, signer) in self.0.iter() {
                    let public_key = hex::encode(public_key);
                    let signer = signer.as_json();
                    seq.serialize_element(&StoredDataItem(&public_key, &signer))?;
                }
                seq.end()
            }
        }

        serde_json::to_string(&StoredData(&self.keys)).trust_me()
    }

    fn get_entries(&self) -> Vec<SignerEntry> {
        self.keys
            .values()
            .map(|key| SignerEntry {
                public_key: *key.public_key(),
                account_id: key.inner.mnemonic_type.account_id(),
            })
            .collect()
    }

    async fn remove_key(&mut self, public_key: &PublicKey) -> Option<SignerEntry> {
        let entry = self.keys.remove(public_key.as_bytes())?;
        Some(SignerEntry {
            public_key: entry.inner.pubkey,
            account_id: entry.inner.mnemonic_type.account_id(),
        })
    }

    async fn clear(&mut self) {
        self.keys.clear();
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyCreateInput {
    pub phrase: SecUtf8,
    pub mnemonic_type: MnemonicType,
    pub password: SecUtf8,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedKeyPassword {
    #[serde(with = "crate::utils::serde_public_key")]
    pub public_key: PublicKey,
    pub password: SecUtf8,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyExportOutput {
    pub phrase: SecUtf8,
    pub mnemonic_type: MnemonicType,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyUpdateParams {
    #[serde(with = "crate::utils::serde_public_key")]
    pub public_key: PublicKey,
    pub old_password: SecUtf8,
    pub new_password: SecUtf8,
}

const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

#[derive(Clone)]
pub struct EncryptedKey {
    inner: CryptoData,
}

impl EncryptedKey {
    pub fn new(password: SecUtf8, mnemonic_type: MnemonicType, phrase: SecUtf8) -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();

        // prepare nonce
        let mut private_key_nonce = [0u8; NONCE_LENGTH];
        rng.fill(&mut private_key_nonce)
            .map_err(EncryptedKeyError::FailedToGenerateRandomBytes)?;
        let private_key_nonce = Nonce::clone_from_slice(&private_key_nonce);

        let mut seed_phrase_nonce = [0u8; NONCE_LENGTH];
        rng.fill(&mut seed_phrase_nonce)
            .map_err(EncryptedKeyError::FailedToGenerateRandomBytes)?;
        let seed_phrase_nonce = Nonce::clone_from_slice(&seed_phrase_nonce);

        let mut salt = vec![0u8; CREDENTIAL_LEN];
        rng.fill(salt.as_mut_slice())
            .map_err(EncryptedKeyError::FailedToGenerateRandomBytes)?;

        // prepare encryptor
        let encryptor = ChaCha20Poly1305::new(&symmetric_key_from_password(password, &salt));

        let phrase = phrase.unsecure();
        let keypair = derive_from_phrase(phrase, mnemonic_type)?;

        // encrypt private key
        let pubkey = keypair.public;
        let encrypted_private_key =
            encrypt(&encryptor, &private_key_nonce, keypair.secret.as_ref())?;

        // encrypt seed phrase
        let encrypted_seed_phrase = encrypt(&encryptor, &seed_phrase_nonce, phrase.as_ref())?;

        Ok(Self {
            inner: CryptoData {
                mnemonic_type,
                pubkey,
                encrypted_private_key,
                private_key_nonce,
                encrypted_seed_phrase,
                seed_phrase_nonce,
                salt,
            },
        })
    }

    pub fn get_mnemonic(&self, password: SecUtf8) -> Result<SecUtf8, EncryptedKeyError> {
        let salt = &self.inner.salt;
        let password = symmetric_key_from_password(password, salt);
        let dec = ChaCha20Poly1305::new(&password);
        let data = decrypt_secure(
            &dec,
            &self.inner.seed_phrase_nonce,
            &self.inner.encrypted_seed_phrase,
        )
        .map_err(|_| EncryptedKeyError::FailedToDecryptData)?;
        Ok(SecUtf8::from(
            String::from_utf8(data.unsecure().to_vec())
                .map_err(|_| EncryptedKeyError::FailedToDecryptData)?,
        ))
    }

    pub fn get_key_pair(&self, password: SecUtf8) -> Result<Keypair, EncryptedKeyError> {
        let password = symmetric_key_from_password(password, &self.inner.salt);
        decrypt_key_pair(
            &self.inner.encrypted_private_key,
            &password,
            &self.inner.private_key_nonce,
        )
    }

    pub fn from_reader<T>(reader: T) -> Result<Self>
    where
        T: Read,
    {
        let crypto_data: CryptoData = serde_json::from_reader(reader)?;
        Ok(EncryptedKey { inner: crypto_data })
    }

    pub fn change_password(&mut self, old_password: SecUtf8, new_password: SecUtf8) -> Result<()> {
        let rng = ring::rand::SystemRandom::new();

        // prepare nonce
        let mut new_private_key_nonce = vec![0u8; NONCE_LENGTH];
        rng.fill(&mut new_private_key_nonce)
            .map_err(EncryptedKeyError::FailedToGenerateRandomBytes)?;
        let new_private_key_nonce = Nonce::clone_from_slice(&new_private_key_nonce);

        let mut new_seed_phrase_nonce = [0u8; NONCE_LENGTH];
        rng.fill(&mut new_seed_phrase_nonce)
            .map_err(EncryptedKeyError::FailedToGenerateRandomBytes)?;
        let new_seed_phrase_nonce = Nonce::clone_from_slice(&new_seed_phrase_nonce);

        let mut new_salt = vec![0u8; CREDENTIAL_LEN];
        rng.fill(&mut new_salt)
            .map_err(EncryptedKeyError::FailedToGenerateRandomBytes)?;

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

    pub fn sign(&self, data: &[u8], password: SecUtf8) -> Result<[u8; ed25519::SIGNATURE_LENGTH]> {
        self.inner.sign(data, password)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.inner.pubkey
    }

    pub fn mnemonic_type(&self) -> MnemonicType {
        self.inner.mnemonic_type
    }

    pub fn as_json(&self) -> String {
        serde_json::to_string(&self.inner).trust_me()
    }
}

impl std::fmt::Debug for EncryptedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner.pubkey)
    }
}

///Data, stored on disk in `encrypted_data` filed of config.
#[derive(Serialize, Deserialize, Clone)]
struct CryptoData {
    mnemonic_type: MnemonicType,

    #[serde(with = "serde_public_key")]
    pubkey: PublicKey,

    #[serde(with = "serde_bytes")]
    encrypted_private_key: Vec<u8>,
    #[serde(with = "serde_nonce")]
    private_key_nonce: Nonce,

    #[serde(with = "serde_bytes")]
    encrypted_seed_phrase: Vec<u8>,
    #[serde(with = "serde_nonce")]
    seed_phrase_nonce: Nonce,

    #[serde(with = "serde_bytes")]
    salt: Vec<u8>,
}

impl CryptoData {
    pub fn sign(&self, data: &[u8], password: SecUtf8) -> Result<[u8; ed25519::SIGNATURE_LENGTH]> {
        let key = symmetric_key_from_password(password, &*self.salt);
        let decrypter = ChaCha20Poly1305::new(&key);

        let bytes = decrypt_secure(
            &decrypter,
            &self.private_key_nonce,
            &self.encrypted_private_key,
        )?;
        let secret = SecretKey::from_bytes(bytes.unsecure())
            .map_err(|_| EncryptedKeyError::InvalidPrivateKey)?;
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
) -> Result<ed25519_dalek::Keypair, EncryptedKeyError> {
    let decrypter = ChaCha20Poly1305::new(&key);
    let bytes = decrypt(&decrypter, nonce, encrypted_key)?;
    let secret = SecretKey::from_bytes(&bytes).map_err(|_| EncryptedKeyError::InvalidPrivateKey)?;
    let public = PublicKey::from(&secret);
    Ok(Keypair { secret, public })
}

#[derive(thiserror::Error, Debug)]
pub enum EncryptedKeyError {
    #[error("Failed to generate random bytes")]
    FailedToGenerateRandomBytes(ring::error::Unspecified),
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Failed to decrypt data")]
    FailedToDecryptData,
    #[error("Failed to encrypt data")]
    FailedToEncryptData,
    #[error("Key already exists")]
    KeyAlreadyExists,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Invalid public key")]
    InvalidPublicKey,
}

impl From<SymmetricCryptoError> for EncryptedKeyError {
    fn from(a: SymmetricCryptoError) -> Self {
        match a {
            SymmetricCryptoError::FailedToDecryptData => Self::FailedToDecryptData,
            SymmetricCryptoError::FailedToEncryptData => Self::FailedToEncryptData,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_PASSWORD: &str = "123";
    const TEST_MNEMONIC: &str = "canyon stage apple useful bench lazy grass enact canvas like figure help pave reopen betray exotic nose fetch wagon senior acid across salon alley";

    #[test]
    fn test_init() {
        let password = SecUtf8::from(TEST_PASSWORD);
        EncryptedKey::new(password, MnemonicType::Legacy, TEST_MNEMONIC.into()).unwrap();
    }

    #[test]
    fn test_bad_password() {
        let password = SecUtf8::from(TEST_PASSWORD);
        let signer =
            EncryptedKey::new(password, MnemonicType::Legacy, TEST_MNEMONIC.into()).unwrap();

        println!("{}", signer.as_json());
        let result = signer.sign(b"lol", "lol".into());
        assert!(result.is_err());
    }
}
