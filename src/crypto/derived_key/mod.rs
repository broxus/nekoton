use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{PublicKey, Signer};
use ring::digest;
use ring::rand::SecureRandom;
use secstr::{SecUtf8, SecVec};
use serde::{Deserialize, Serialize, Serializer};

use super::PubKey;
use crate::crypto::mnemonic::*;
use crate::crypto::symmetric::*;
use crate::crypto::{Signer as StoreSigner, SignerEntry, SignerStorage};
use crate::utils::*;

const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

#[derive(Default, Clone, Debug)]
pub struct DerivedKeySigner {
    master_keys: HashMap<[u8; 32], MasterKey>,
}

impl DerivedKeySigner {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_master_key(&self, master_key: &PublicKey) -> Result<&MasterKey> {
        match self.master_keys.get(master_key.as_bytes()) {
            Some(key) => Ok(key),
            None => Err(MasterKeyError::MasterKeyNotFound.into()),
        }
    }
}

#[async_trait]
impl StoreSigner for DerivedKeySigner {
    type CreateKeyInput = DerivedKeyCreateInput;
    type ExportKeyInput = DerivedKeyExportParams;
    type ExportKeyOutput = DerivedKeyExportOutput;
    type UpdateKeyInput = DerivedKeyUpdateParams;
    type SignInput = DerivedKeySignParams;

    async fn add_key(&mut self, input: Self::CreateKeyInput) -> Result<SignerEntry> {
        Ok(match input {
            DerivedKeyCreateInput::Import {
                phrase,
                password,
                name,
            } => {
                let master_key = MasterKey::new(password, phrase, name.clone())?;
                let public_key = master_key.public_key;
                self.master_keys.insert(public_key.to_bytes(), master_key);

                SignerEntry {
                    public_key,
                    master_key: public_key,
                    account_id: 0,
                    name,
                }
            }
            DerivedKeyCreateInput::Derive {
                master_key,
                account_id,
                password,
                name,
            } => {
                let master_key = match self.master_keys.get_mut(master_key.as_bytes()) {
                    Some(key) => key,
                    None => return Err(MasterKeyError::MasterKeyNotFound.into()),
                };

                let decrypter =
                    ChaCha20Poly1305::new(&symmetric_key_from_password(password, &master_key.salt));

                let master = decrypt_secure(
                    &decrypter,
                    &master_key.entropy_nonce,
                    &*master_key.enc_entropy,
                )?;

                let public_key = derive_from_master(account_id, master)?.public;
                master_key
                    .accounts_map
                    .insert(public_key.to_bytes(), Account(account_id, name.clone()));

                SignerEntry {
                    public_key,
                    master_key: master_key.public_key,
                    account_id,
                    name,
                }
            }
        })
    }

    async fn update_key(&mut self, input: Self::UpdateKeyInput) -> Result<SignerEntry> {
        let master_key = match self.master_keys.get_mut(input.master_key.as_bytes()) {
            Some(key) => key,
            None => return Err(MasterKeyError::MasterKeyNotFound.into()),
        };

        master_key.change_password(input.old_password, input.new_password)?;
        Ok(SignerEntry {
            public_key: master_key.public_key,
            master_key: master_key.public_key,
            account_id: 0,
            name: "".to_string(), //todo where can i get name?
        })
    }

    async fn export_key(&self, input: Self::ExportKeyInput) -> Result<Self::ExportKeyOutput> {
        let master_key = match self.master_keys.get(input.master_key.as_bytes()) {
            Some(key) => key,
            None => return Err(MasterKeyError::MasterKeyNotFound.into()),
        };

        let decrypter = ChaCha20Poly1305::new(&symmetric_key_from_password(
            input.password,
            &master_key.salt,
        ));

        let phrase = decrypt_secure(
            &decrypter,
            &master_key.phrase_nonce,
            &*master_key.enc_phrase,
        )?;

        Ok(Self::ExportKeyOutput {
            phrase: SecUtf8::from(String::from_utf8(phrase.unsecure().to_vec())?),
        })
    }

    async fn sign(&self, data: &[u8], input: Self::SignInput) -> Result<[u8; 64]> {
        let (master_key, account_id, password) = match input {
            Self::SignInput::ByAccountId {
                master_key,
                account_id,
                password,
            } => (self.get_master_key(&master_key)?, account_id, password),
            Self::SignInput::ByPublicKey {
                master_key,
                public_key,
                password,
            } => {
                let master_key = self.get_master_key(&master_key)?;
                match master_key.accounts_map.get(public_key.as_bytes()) {
                    Some(account_id) => (master_key, account_id.0, password),
                    None => return Err(MasterKeyError::DerivedKeyNotFound.into()),
                }
            }
        };

        let decrypter =
            ChaCha20Poly1305::new(&symmetric_key_from_password(password, &master_key.salt));

        let master = decrypt_secure(
            &decrypter,
            &master_key.entropy_nonce,
            &master_key.enc_entropy,
        )?;

        let signer = derive_from_master(account_id, master)?;
        Ok(signer.sign(data).to_bytes())
    }
}

#[async_trait]
impl SignerStorage for DerivedKeySigner {
    fn load_state(&mut self, data: &str) -> Result<()> {
        #[derive(Deserialize)]
        struct ParsedDerivedKeySigner {
            master_keys: HashMap<String, MasterKey>,
        }

        if let Ok(state) = serde_json::from_str::<ParsedDerivedKeySigner>(data) {
            self.master_keys = state
                .master_keys
                .into_iter()
                .map(|(public_key, master_key)| {
                    let public_key = hex::decode(&public_key)?;
                    let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key)?;
                    Result::<_, anyhow::Error>::Ok((public_key.to_bytes(), master_key))
                })
                .collect::<Result<HashMap<_, _>, _>>()?;
        } else {
            let mut master_keys = HashMap::with_capacity(1);
            if let Some(master_key) = serde_json::from_str::<Option<MasterKey>>(data)? {
                master_keys.insert(master_key.public_key.to_bytes(), master_key);
            }
            self.master_keys = master_keys;
        }

        Ok(())
    }

    fn store_state(&self) -> String {
        struct StoredMasterKeys<'a>(&'a HashMap<[u8; 32], MasterKey>);

        impl<'a> Serialize for StoredMasterKeys<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                use serde::ser::SerializeMap;

                let mut map = serializer.serialize_map(Some(self.0.len()))?;
                for (public_key, master_key) in self.0.iter() {
                    map.serialize_entry(&hex::encode(public_key), master_key)?;
                }

                map.end()
            }
        }

        #[derive(Serialize)]
        struct StoredDerivedKeySigner<'a> {
            master_keys: StoredMasterKeys<'a>,
        }

        serde_json::to_string(&StoredDerivedKeySigner {
            master_keys: StoredMasterKeys(&self.master_keys),
        })
        .trust_me()
    }

    fn get_entries(&self) -> Vec<SignerEntry> {
        self.master_keys
            .values()
            .flat_map(|key: &MasterKey| {
                let master_key = key.public_key;
                key.accounts_map
                    .iter()
                    .map(move |(public_key, account_id)| SignerEntry {
                        public_key: PublicKey::from_bytes(public_key).trust_me(),
                        master_key,
                        account_id: account_id.0,
                        name: account_id.1.clone(),
                    })
            })
            .collect()
    }

    async fn remove_key(&mut self, public_key: &PublicKey) -> Option<SignerEntry> {
        for master_key in self.master_keys.values_mut() {
            if let Some(account_id) = master_key.accounts_map.remove(public_key.as_bytes()) {
                return Some(SignerEntry {
                    public_key: *public_key,
                    master_key: master_key.public_key,
                    account_id: account_id.0,
                    name: account_id.1,
                });
            }
        }

        None
    }

    async fn clear(&mut self) {
        for master_key in self.master_keys.values_mut() {
            master_key.accounts_map.clear();
        }
        self.master_keys.clear();
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct MasterKey {
    #[serde(with = "serde_public_key")]
    public_key: PublicKey,

    #[serde(with = "serde_bytes")]
    salt: Vec<u8>,

    #[serde(with = "serde_bytes")]
    enc_entropy: Vec<u8>,

    #[serde(with = "serde_nonce")]
    entropy_nonce: Nonce,

    #[serde(with = "serde_bytes")]
    enc_phrase: Vec<u8>,

    #[serde(with = "serde_nonce")]
    phrase_nonce: Nonce,

    #[serde(with = "serde_accounts_map")]
    accounts_map: AccountsMap,
}

impl MasterKey {
    fn new(password: SecUtf8, phrase: SecUtf8, name: String) -> Result<Self> {
        use zeroize::Zeroize;

        let mut phrase = phrase.unsecure().to_string();

        // SECURITY: private key will be zeroized here
        let public_key = derive_from_phrase(&phrase, MnemonicType::Labs(0))?.public;

        let mut entropy = labs::derive_master_key(&phrase)?;
        let EncryptedPart {
            salt,
            enc_entropy,
            entropy_nonce,
            enc_phrase,
            phrase_nonce,
        } = compute_encrypted_part(&entropy, phrase.as_bytes(), password)?;

        phrase.zeroize();
        entropy.zeroize();

        let mut accounts_map = AccountsMap::new();
        accounts_map.insert(public_key.to_bytes(), Account(0, name));

        Ok(Self {
            public_key,
            salt,
            enc_entropy,
            entropy_nonce,
            enc_phrase,
            phrase_nonce,
            accounts_map,
        })
    }

    fn change_password(&mut self, old_password: SecUtf8, new_password: SecUtf8) -> Result<()> {
        let decrypter =
            ChaCha20Poly1305::new(&symmetric_key_from_password(old_password, &self.salt));

        let entropy = decrypt_secure(&decrypter, &self.entropy_nonce, &self.enc_entropy)?;
        let phrase = decrypt_secure(&decrypter, &self.phrase_nonce, &self.enc_phrase)?;

        let encrypted_part =
            compute_encrypted_part(entropy.unsecure(), phrase.unsecure(), new_password)?;
        self.salt = encrypted_part.salt;
        self.enc_entropy = encrypted_part.enc_entropy;
        self.entropy_nonce = encrypted_part.entropy_nonce;
        self.enc_phrase = encrypted_part.enc_phrase;
        self.phrase_nonce = encrypted_part.phrase_nonce;

        Ok(())
    }
}

fn compute_encrypted_part(
    entropy: &[u8],
    phrase: &[u8],
    password: SecUtf8,
) -> Result<EncryptedPart> {
    let rng = ring::rand::SystemRandom::new();

    let mut salt = vec![0u8; CREDENTIAL_LEN];
    rng.fill(salt.as_mut_slice())
        .map_err(|_| MasterKeyError::FailedToGenerateRandomBytes)?;

    let mut entropy_nonce = [0u8; NONCE_LENGTH];
    rng.fill(&mut entropy_nonce)
        .map_err(|_| MasterKeyError::FailedToGenerateRandomBytes)?;

    let mut phrase_nonce = [0u8; NONCE_LENGTH];
    rng.fill(&mut phrase_nonce)
        .map_err(|_| MasterKeyError::FailedToGenerateRandomBytes)?;

    let entropy_nonce = Nonce::clone_from_slice(entropy_nonce.as_ref());
    let phrase_nonce = Nonce::clone_from_slice(phrase_nonce.as_ref());

    let encryptor = ChaCha20Poly1305::new(&symmetric_key_from_password(password, &salt));
    let enc_entropy = encrypt(&encryptor, &entropy_nonce, entropy)?;
    let enc_phrase = encrypt(&encryptor, &phrase_nonce, phrase)?;

    Ok(EncryptedPart {
        salt,
        enc_entropy,
        entropy_nonce,
        enc_phrase,
        phrase_nonce,
    })
}

struct EncryptedPart {
    salt: Vec<u8>,
    enc_entropy: Vec<u8>,
    entropy_nonce: Nonce,
    enc_phrase: Vec<u8>,
    phrase_nonce: Nonce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Account(pub u16, pub String);

type AccountsMap = HashMap<PubKey, Account>;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum DerivedKeySignParams {
    ByAccountId {
        #[serde(with = "serde_public_key")]
        master_key: PublicKey,
        account_id: u16,
        password: SecUtf8,
    },
    ByPublicKey {
        #[serde(with = "serde_public_key")]
        master_key: PublicKey,
        #[serde(with = "serde_public_key")]
        public_key: PublicKey,
        password: SecUtf8,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DerivedKeyExportParams {
    #[serde(with = "serde_public_key")]
    pub master_key: PublicKey,
    pub password: SecUtf8,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DerivedKeyExportOutput {
    pub phrase: SecUtf8,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DerivedKeyUpdateParams {
    #[serde(with = "serde_public_key")]
    pub master_key: PublicKey,
    pub old_password: SecUtf8,
    pub new_password: SecUtf8,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DerivedKeyCreateInput {
    Import {
        phrase: SecUtf8,
        password: SecUtf8,
        name: String,
    },
    Derive {
        #[serde(with = "serde_public_key")]
        master_key: PublicKey,
        account_id: u16,
        password: SecUtf8,
        name: String,
    },
}

mod serde_accounts_map {
    use std::collections::HashMap;
    use std::convert::TryInto;

    use serde::de::Error;
    use serde::ser::SerializeMap;
    use serde::{Deserialize, Serialize};

    use super::*;

    pub fn serialize<S>(data: &AccountsMap, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct StoredItem {
            account_id: u16,
            name: String,
        }

        let mut map = serializer.serialize_map(Some(data.len()))?;
        for (pubkey, account_id) in data.iter() {
            map.serialize_entry(
                &hex::encode(pubkey),
                &StoredItem {
                    account_id: *account_id,
                },
            )?;
        }

        map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<AccountsMap, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StoredItem {
            account_id: u16,
        }

        let stored_data = HashMap::<String, StoredItem>::deserialize(deserializer)?;
        stored_data
            .into_iter()
            .map(|(public_key, StoredItem { account_id })| {
                let public_key = hex::decode(&public_key)
                    .map_err(D::Error::custom)
                    .and_then(|public_key| {
                        public_key
                            .try_into()
                            .map_err(|_| D::Error::custom("Invalid public key"))
                    })?;
                Ok((public_key, account_id))
            })
            .collect::<Result<_, _>>()
    }
}

fn derive_from_master(id: u16, master: SecVec<u8>) -> Result<ed25519_dalek::Keypair> {
    use tiny_hderive::bip32;

    let path = format!("m/44'/396'/0'/0/{}", id);
    let key = bip32::ExtendedPrivKey::derive(master.unsecure(), path.as_str())
        .map_err(|_| MasterKeyError::DerivationError)?
        .secret();
    drop(master);
    let secret =
        ed25519_dalek::SecretKey::from_bytes(&key).map_err(|_| MasterKeyError::DerivationError)?;
    let public = ed25519_dalek::PublicKey::from(&secret);
    Ok(ed25519_dalek::Keypair { secret, public })
}

#[derive(Debug, thiserror::Error)]
enum MasterKeyError {
    #[error("Master key not found")]
    MasterKeyNotFound,
    #[error("Derived key not found")]
    DerivedKeyNotFound,
    #[error("Failed to derive account from master key")]
    DerivationError,
    #[error("Failed to generate random bytes")]
    FailedToGenerateRandomBytes,
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_PHRASE: &str =
        "pioneer fever hazard scan install wise reform corn bubble leisure amazing note";

    #[tokio::test]
    async fn test_creation() -> Result<()> {
        let mut signer = DerivedKeySigner::new();

        signer
            .add_key(DerivedKeyCreateInput::Import {
                phrase: SecUtf8::from(TEST_PHRASE),
                password: SecUtf8::from("123"),
            })
            .await?;

        assert!(!signer.master_keys.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_change_password() -> Result<()> {
        let mut signer = DerivedKeySigner::new();
        let entry = signer
            .add_key(DerivedKeyCreateInput::Import {
                phrase: SecUtf8::from(TEST_PHRASE),
                password: SecUtf8::from("123"),
            })
            .await?;

        signer
            .update_key(DerivedKeyUpdateParams {
                master_key: entry.master_key,
                old_password: "123".to_owned().into(),
                new_password: "321".to_owned().into(),
            })
            .await?;

        assert!(signer
            .update_key(DerivedKeyUpdateParams {
                master_key: entry.master_key,
                old_password: SecUtf8::from("totally different"),
                new_password: SecUtf8::from("321"),
            })
            .await
            .is_err());

        Ok(())
    }
}
