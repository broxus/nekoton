use std::collections::hash_map::{self, HashMap};

use anyhow::Result;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::{Keypair, PublicKey};
use secstr::SecUtf8;
use serde::{Deserialize, Serialize, Serializer};

use super::mnemonic::*;
use super::{
    default_key_name, Password, PasswordCache, PasswordCacheTransaction, PubKey, SharedSecret,
    SignatureContext, Signer as StoreSigner, SignerContext, SignerEntry, SignerStorage,
};
use nekoton_utils::*;

#[derive(Default, Clone, Debug, Eq, PartialEq)]
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

    fn use_sign_input(
        &'_ self,
        password_cache: &PasswordCache,
        input: DerivedKeyPassword,
    ) -> Result<Keypair> {
        let (master_key, account_id, password) = match input {
            DerivedKeyPassword::ByAccountId {
                master_key,
                account_id,
                password,
            } => (self.get_master_key(&master_key)?, account_id, password),
            DerivedKeyPassword::ByPublicKey {
                master_key,
                public_key,
                password,
            } => {
                let master_key = self.get_master_key(&master_key)?;
                match master_key.accounts_map.get(public_key.as_bytes()) {
                    Some(account) => (master_key, account.account_id, password),
                    None => return Err(MasterKeyError::DerivedKeyNotFound.into()),
                }
            }
        };

        let password =
            password_cache.process_password(master_key.public_key.to_bytes(), password)?;

        let decrypter = ChaCha20Poly1305::new(&symmetric_key_from_password(
            password.as_ref(),
            &master_key.salt,
        ));

        let master = decrypt_secure(
            &decrypter,
            &master_key.entropy_nonce,
            &master_key.enc_entropy,
        )?;

        let signer = derive_from_master(account_id, master.unsecure())?;

        password.proceed();
        Ok(signer)
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
impl StoreSigner for DerivedKeySigner {
    type CreateKeyInput = DerivedKeyCreateInput;
    type ExportSeedInput = DerivedKeyExportSeedParams;
    type ExportSeedOutput = DerivedKeyExportSeedOutput;
    type ExportKeypairInput = DerivedKeyPassword;
    type ExportKeypairOutput = Keypair;
    type GetPublicKeys = DerivedKeyGetPublicKeys;
    type UpdateKeyInput = DerivedKeyUpdateParams;
    type SignInput = DerivedKeyPassword;

    async fn add_key(
        &mut self,
        ctx: SignerContext<'_>,
        input: Self::CreateKeyInput,
    ) -> Result<SignerEntry> {
        Ok(match input {
            DerivedKeyCreateInput::Import {
                phrase,
                password,
                key_name,
            } => {
                let (master_key, key_name, password) =
                    MasterKey::new(ctx.password_cache, password, phrase, key_name)?;
                let public_key = master_key.public_key;

                match self.master_keys.entry(public_key.to_bytes()) {
                    hash_map::Entry::Vacant(entry) => {
                        entry.insert(master_key);
                    }
                    hash_map::Entry::Occupied(mut entry) => {
                        let existing = entry.get_mut();
                        existing.salt = master_key.salt;
                        existing.enc_entropy = master_key.enc_entropy;
                        existing.entropy_nonce = master_key.entropy_nonce;
                        existing.enc_phrase = master_key.enc_phrase;
                        existing.phrase_nonce = master_key.phrase_nonce;

                        match existing.accounts_map.entry(public_key.to_bytes()) {
                            hash_map::Entry::Vacant(entry) => {
                                entry.insert(Account {
                                    name: key_name.clone(),
                                    account_id: 0,
                                });
                            }
                            hash_map::Entry::Occupied(mut entry) => {
                                entry.get_mut().name = key_name.clone();
                            }
                        }
                    }
                };

                password.proceed();
                SignerEntry {
                    name: key_name,
                    public_key,
                    master_key: public_key,
                    account_id: 0,
                }
            }
            DerivedKeyCreateInput::Derive {
                master_key,
                account_id,
                password,
                key_name,
            } => {
                let master_key = match self.master_keys.get_mut(master_key.as_bytes()) {
                    Some(key) => key,
                    None => return Err(MasterKeyError::MasterKeyNotFound.into()),
                };

                let found = master_key
                    .accounts_map
                    .values()
                    .any(|x| x.account_id == account_id);
                if found {
                    return Err(MasterKeyError::DerivedKeyExists.into());
                }

                let password = ctx
                    .password_cache
                    .process_password(master_key.public_key.to_bytes(), password)?;

                let decrypter = ChaCha20Poly1305::new(&symmetric_key_from_password(
                    password.as_ref(),
                    &master_key.salt,
                ));

                let master = decrypt_secure(
                    &decrypter,
                    &master_key.entropy_nonce,
                    &master_key.enc_entropy,
                )?;

                let public_key = derive_from_master(account_id, master.unsecure())?.public;

                let key_name = key_name.unwrap_or_else(|| default_key_name(public_key.as_bytes()));

                master_key.accounts_map.insert(
                    public_key.to_bytes(),
                    Account {
                        name: key_name.clone(),
                        account_id,
                    },
                );

                password.proceed();
                SignerEntry {
                    name: key_name,
                    public_key,
                    master_key: master_key.public_key,
                    account_id,
                }
            }
        })
    }

    async fn update_key(
        &mut self,
        ctx: SignerContext<'_>,
        input: Self::UpdateKeyInput,
    ) -> Result<SignerEntry> {
        match input {
            Self::UpdateKeyInput::RenameKey {
                master_key,
                public_key,
                name,
            } => {
                let entry = match self.master_keys.get_mut(master_key.as_bytes()) {
                    Some(key) => key,
                    None => return Err(MasterKeyError::MasterKeyNotFound.into()),
                };

                let entry = match entry.accounts_map.get_mut(public_key.as_bytes()) {
                    Some(entry) => entry,
                    None => return Err(MasterKeyError::DerivedKeyNotFound.into()),
                };

                entry.name = name.clone();

                Ok(SignerEntry {
                    name,
                    public_key,
                    master_key,
                    account_id: entry.account_id,
                })
            }
            Self::UpdateKeyInput::ChangePassword {
                master_key,
                old_password,
                new_password,
            } => {
                let entry = match self.master_keys.get_mut(master_key.as_bytes()) {
                    Some(key) => key,
                    None => return Err(MasterKeyError::MasterKeyNotFound.into()),
                };

                let old_password = ctx
                    .password_cache
                    .process_password(master_key.to_bytes(), old_password)?;
                let new_password = ctx
                    .password_cache
                    .process_password(master_key.to_bytes(), new_password)?;

                entry.change_password(old_password.as_ref(), new_password.as_ref())?;

                let name = entry
                    .accounts_map
                    .get(master_key.as_bytes())
                    .map(|item| item.name.clone())
                    .unwrap_or_default();

                new_password.proceed();
                Ok(SignerEntry {
                    name,
                    public_key: entry.public_key,
                    master_key: entry.public_key,
                    account_id: 0,
                })
            }
        }
    }

    async fn export_seed(
        &self,
        ctx: SignerContext<'_>,
        input: Self::ExportSeedInput,
    ) -> Result<Self::ExportSeedOutput> {
        let master_key = match self.master_keys.get(input.master_key.as_bytes()) {
            Some(key) => key,
            None => return Err(MasterKeyError::MasterKeyNotFound.into()),
        };

        let password = ctx
            .password_cache
            .process_password(master_key.public_key.to_bytes(), input.password)?;

        let decrypter = ChaCha20Poly1305::new(&symmetric_key_from_password(
            password.as_ref(),
            &master_key.salt,
        ));

        let phrase = decrypt_secure(&decrypter, &master_key.phrase_nonce, &master_key.enc_phrase)?;

        let phrase = SecUtf8::from(String::from_utf8(phrase.unsecure().to_vec())?);

        password.proceed();
        Ok(Self::ExportSeedOutput { phrase })
    }

    async fn export_keypair(
        &self,
        ctx: SignerContext<'_>,
        input: Self::ExportKeypairInput,
    ) -> Result<Self::ExportKeypairOutput> {
        self.use_sign_input(ctx.password_cache, input)
    }

    async fn get_public_keys(
        &self,
        ctx: SignerContext<'_>,
        input: Self::GetPublicKeys,
    ) -> Result<Vec<PublicKey>> {
        let master_key = match self.master_keys.get(input.master_key.as_bytes()) {
            Some(key) => key,
            None => return Err(MasterKeyError::MasterKeyNotFound.into()),
        };

        let password = ctx
            .password_cache
            .process_password(master_key.public_key.to_bytes(), input.password)?;

        let decrypter = ChaCha20Poly1305::new(&symmetric_key_from_password(
            password.as_ref(),
            &master_key.salt,
        ));

        let master = decrypt_secure(
            &decrypter,
            &master_key.entropy_nonce,
            &master_key.enc_entropy,
        )?;

        let public_keys = (input.offset..input.offset.saturating_add(input.limit))
            .map(|account_id| {
                derive_from_master(account_id, master.unsecure()).map(|key| key.public)
            })
            .collect::<Result<Vec<PublicKey>>>()?;

        password.proceed();
        Ok(public_keys)
    }

    async fn compute_shared_secrets(
        &self,
        ctx: SignerContext<'_>,
        public_keys: &[PublicKey],
        input: Self::SignInput,
    ) -> Result<Vec<SharedSecret>> {
        let keypair = self.use_sign_input(ctx.password_cache, input)?;
        Ok(public_keys
            .iter()
            .map(|public_key| {
                let secret = super::x25519::compute_shared(&keypair.secret, public_key);
                SharedSecret {
                    source_public_key: keypair.public,
                    recipient_public_key: *public_key,
                    secret,
                }
            })
            .collect())
    }

    async fn sign(
        &self,
        ctx: SignerContext<'_>,
        data: &[u8],
        signature_ctx: SignatureContext,
        input: Self::SignInput,
    ) -> Result<[u8; 64]> {
        let keypair = self.use_sign_input(ctx.password_cache, input)?;
        let signature = signature_ctx.sign(&keypair, data);
        Ok(signature.to_bytes())
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
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
                    let public_key = hex::decode(public_key)?;
                    let public_key = PublicKey::from_bytes(&public_key)?;
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

        impl Serialize for StoredMasterKeys<'_> {
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
                        name: account_id.name.clone(),
                        public_key: PublicKey::from_bytes(public_key).trust_me(),
                        master_key,
                        account_id: account_id.account_id,
                    })
            })
            .collect()
    }

    async fn remove_key(&mut self, public_key: &PublicKey) -> Option<SignerEntry> {
        for master_key in self.master_keys.values_mut() {
            if let Some(account) = master_key.accounts_map.remove(public_key.as_bytes()) {
                return Some(SignerEntry {
                    name: account.name,
                    public_key: *public_key,
                    master_key: master_key.public_key,
                    account_id: account.account_id,
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

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
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
    fn new(
        password_cache: &'_ PasswordCache,
        password: Password,
        phrase: SecUtf8,
        key_name: Option<String>,
    ) -> Result<(Self, String, PasswordCacheTransaction<'_>)> {
        use zeroize::Zeroize;

        let mut phrase = phrase.unsecure().to_string();

        // SECURITY: private key will be zeroized here
        let public_key =
            derive_from_phrase(&phrase, MnemonicType::Bip39(Bip39MnemonicData::labs_old(0)))?
                .public;

        let key_name = key_name.unwrap_or_else(|| default_key_name(public_key.as_bytes()));

        let password = password_cache.process_password(public_key.to_bytes(), password)?;

        let mut entropy = labs::derive_master_key(&phrase)?;
        let EncryptedPart {
            salt,
            enc_entropy,
            entropy_nonce,
            enc_phrase,
            phrase_nonce,
        } = compute_encrypted_part(&entropy, phrase.as_bytes(), password.as_ref())?;

        phrase.zeroize();
        entropy.zeroize();

        let mut accounts_map = AccountsMap::new();
        accounts_map.insert(
            public_key.to_bytes(),
            Account {
                name: key_name.clone(),
                account_id: 0,
            },
        );

        Ok((
            Self {
                public_key,
                salt,
                enc_entropy,
                entropy_nonce,
                enc_phrase,
                phrase_nonce,
                accounts_map,
            },
            key_name,
            password,
        ))
    }

    fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
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

fn compute_encrypted_part(entropy: &[u8], phrase: &[u8], password: &str) -> Result<EncryptedPart> {
    use rand::Rng;

    let rng = &mut rand::thread_rng();

    let mut salt = vec![0u8; 32];
    rng.fill(salt.as_mut_slice());

    let mut entropy_nonce = [0u8; NONCE_LENGTH];
    rng.fill(&mut entropy_nonce);

    let mut phrase_nonce = [0u8; NONCE_LENGTH];
    rng.fill(&mut phrase_nonce);

    let entropy_nonce = Nonce::from(entropy_nonce);
    let phrase_nonce = Nonce::from(phrase_nonce);

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

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
struct Account {
    name: String,
    account_id: u16,
}

type AccountsMap = HashMap<PubKey, Account>;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum DerivedKeyPassword {
    ByAccountId {
        #[serde(with = "serde_public_key")]
        master_key: PublicKey,
        account_id: u16,
        password: Password,
    },
    ByPublicKey {
        #[serde(with = "serde_public_key")]
        master_key: PublicKey,
        #[serde(with = "serde_public_key")]
        public_key: PublicKey,
        password: Password,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DerivedKeyExportSeedParams {
    #[serde(with = "serde_public_key")]
    pub master_key: PublicKey,
    pub password: Password,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DerivedKeyExportSeedOutput {
    pub phrase: SecUtf8,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DerivedKeyGetPublicKeys {
    #[serde(with = "serde_public_key")]
    pub master_key: PublicKey,
    pub password: Password,
    pub limit: u16,
    pub offset: u16,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum DerivedKeyUpdateParams {
    RenameKey {
        #[serde(with = "serde_public_key")]
        master_key: PublicKey,
        #[serde(with = "serde_public_key")]
        public_key: PublicKey,
        name: String,
    },
    ChangePassword {
        #[serde(with = "serde_public_key")]
        master_key: PublicKey,
        old_password: Password,
        new_password: Password,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum DerivedKeyCreateInput {
    Import {
        key_name: Option<String>,
        phrase: SecUtf8,
        password: Password,
    },
    Derive {
        key_name: Option<String>,
        #[serde(with = "serde_public_key")]
        master_key: PublicKey,
        account_id: u16,
        password: Password,
    },
}

mod serde_accounts_map {
    use std::collections::HashMap;
    use std::convert::TryInto;

    use serde::de::Error;
    use serde::ser::SerializeMap;
    use serde::{Deserialize, Serialize};

    use super::*;

    pub(super) fn serialize<S>(data: &AccountsMap, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct StoredItem<'a> {
            name: &'a str,
            account_id: u16,
        }

        let mut map = serializer.serialize_map(Some(data.len()))?;
        for (pubkey, account) in data.iter() {
            map.serialize_entry(
                &hex::encode(pubkey),
                &StoredItem {
                    name: &account.name,
                    account_id: account.account_id,
                },
            )?;
        }

        map.end()
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<AccountsMap, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StoredItem {
            #[serde(default)]
            name: Option<String>,
            account_id: u16,
        }

        let stored_data = HashMap::<String, StoredItem>::deserialize(deserializer)?;
        stored_data
            .into_iter()
            .map(|(public_key, StoredItem { name, account_id })| {
                let public_key =
                    hex::decode(public_key)
                        .map_err(D::Error::custom)
                        .and_then(|public_key| {
                            public_key
                                .try_into()
                                .map_err(|_| D::Error::custom("Invalid public key"))
                        })?;
                let name = name.unwrap_or_else(|| default_key_name(&public_key));
                Ok((public_key, Account { name, account_id }))
            })
            .collect::<Result<_, _>>()
    }
}

fn derive_from_master(id: u16, master: &[u8]) -> Result<ed25519_dalek::Keypair> {
    use tiny_hderive::bip32;

    let path = format!("m/44'/396'/0'/0/{id}");
    let key = bip32::ExtendedPrivKey::derive(master, path.as_str())
        .map_err(|_| MasterKeyError::DerivationError)?
        .secret();

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
    #[error("Derived key already exists")]
    DerivedKeyExists,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::crypto::PasswordCacheBehavior;

    const TEST_PHRASE: &str =
        "pioneer fever hazard scan install wise reform corn bubble leisure amazing note";

    #[tokio::test]
    async fn test_creation() -> Result<()> {
        let mut signer = DerivedKeySigner::new();

        let cache = PasswordCache::new();
        let ctx = SignerContext {
            password_cache: &cache,
        };

        // First import
        let entry = signer
            .add_key(
                ctx,
                DerivedKeyCreateInput::Import {
                    key_name: Some("Key".to_owned()),
                    phrase: SecUtf8::from(TEST_PHRASE),
                    password: Password::Explicit {
                        password: SecUtf8::from("123"),
                        cache_behavior: PasswordCacheBehavior::Store(Duration::from_secs(1)),
                    },
                },
            )
            .await?;

        assert!(!signer.master_keys.is_empty());

        signer
            .export_seed(
                ctx,
                DerivedKeyExportSeedParams {
                    master_key: entry.master_key,
                    password: Password::FromCache,
                },
            )
            .await
            .unwrap();

        signer
            .export_keypair(
                ctx,
                DerivedKeyPassword::ByAccountId {
                    master_key: entry.master_key,
                    account_id: 0,
                    password: Password::FromCache,
                },
            )
            .await
            .unwrap();

        // Second import with same seed
        let entry = signer
            .add_key(
                ctx,
                DerivedKeyCreateInput::Import {
                    key_name: Some("Key 2".to_owned()),
                    phrase: SecUtf8::from(TEST_PHRASE),
                    password: Password::Explicit {
                        password: SecUtf8::from("321"),
                        cache_behavior: PasswordCacheBehavior::Remove,
                    },
                },
            )
            .await?;

        assert!(!signer.master_keys.is_empty());

        signer
            .export_seed(
                ctx,
                DerivedKeyExportSeedParams {
                    master_key: entry.master_key,
                    password: Password::Explicit {
                        password: SecUtf8::from("321"),
                        cache_behavior: PasswordCacheBehavior::Store(Duration::from_secs(1)),
                    },
                },
            )
            .await
            .unwrap();

        Ok(())
    }

    #[tokio::test]
    async fn test_change_password() -> Result<()> {
        let mut signer = DerivedKeySigner::new();

        let cache = PasswordCache::new();
        let ctx = SignerContext {
            password_cache: &cache,
        };

        let entry = signer
            .add_key(
                ctx,
                DerivedKeyCreateInput::Import {
                    key_name: Some("Key".to_owned()),
                    phrase: SecUtf8::from(TEST_PHRASE),
                    password: Password::Explicit {
                        password: SecUtf8::from("123"),
                        cache_behavior: Default::default(),
                    },
                },
            )
            .await?;

        signer
            .update_key(
                ctx,
                DerivedKeyUpdateParams::ChangePassword {
                    master_key: entry.master_key,
                    old_password: Password::Explicit {
                        password: SecUtf8::from("123"),
                        cache_behavior: Default::default(),
                    },
                    new_password: Password::Explicit {
                        password: SecUtf8::from("321"),
                        cache_behavior: Default::default(),
                    },
                },
            )
            .await?;

        assert!(signer
            .update_key(
                ctx,
                DerivedKeyUpdateParams::ChangePassword {
                    master_key: entry.master_key,
                    old_password: Password::Explicit {
                        password: SecUtf8::from("totally different"),
                        cache_behavior: Default::default(),
                    },
                    new_password: Password::Explicit {
                        password: SecUtf8::from("321"),
                        cache_behavior: Default::default(),
                    },
                }
            )
            .await
            .is_err());

        Ok(())
    }

    #[tokio::test]
    async fn migrate_accounts_map() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug)]
        struct Wr(#[serde(with = "super::serde_accounts_map")] AccountsMap);

        let map_str = r#"{"3030303030303030303030303030303030303030303030303030303030303030":{"account_id":0},"3030303030303030303030303030303030303030303030303030303030303031":{"account_id":1}}"#;
        let wr: Wr = serde_json::from_str(map_str).unwrap();
        assert_eq!(
            wr.0[b"00000000000000000000000000000000"].name,
            "3030...3030"
        );
        let map_str = r#"{"3030303030303030303030303030303030303030303030303030303030303030":{"account_id":0, "name":"lil"},"3030303030303030303030303030303030303030303030303030303030303031":{"account_id":1}}"#;
        let wr: Wr = serde_json::from_str(map_str).unwrap();
        assert_eq!(wr.0[b"00000000000000000000000000000000"].name, "lil");
    }

    #[tokio::test]
    async fn store_load() {
        let mut key = DerivedKeySigner::new();

        let cache = PasswordCache::new();
        let ctx = SignerContext {
            password_cache: &cache,
        };

        let master = key
            .add_key(
                ctx,
                DerivedKeyCreateInput::Import {
                    key_name: Some("from giver".into()),
                    phrase: TEST_PHRASE.into(),
                    password: Password::Explicit {
                        password: SecUtf8::from("supasecret"),
                        cache_behavior: Default::default(),
                    },
                },
            )
            .await
            .unwrap()
            .master_key;
        key.add_key(
            ctx,
            DerivedKeyCreateInput::Derive {
                key_name: Some("all my money 🤑".into()),
                master_key: master,
                password: Password::Explicit {
                    password: SecUtf8::from("supasecret"),
                    cache_behavior: Default::default(),
                },
                account_id: 1,
            },
        )
        .await
        .unwrap();
        key.add_key(
            ctx,
            DerivedKeyCreateInput::Derive {
                key_name: Some("史萊克的模因.".into()),
                master_key: master,
                password: Password::Explicit {
                    password: SecUtf8::from("supasecret"),
                    cache_behavior: Default::default(),
                },
                account_id: 2,
            },
        )
        .await
        .unwrap();
        let serialized = key.store_state();

        let mut loaded = DerivedKeySigner::new();
        loaded.load_state(&serialized).unwrap();
        assert_eq!(loaded, key);
    }

    #[tokio::test]
    async fn load_old() {
        let json = r#"{
    "master_keys": {
        "4ebe5acc31dea9432b6b83470d7b4594a3f24fccbd60d78a2e92a5e441339a89": {
            "public_key": "4ebe5acc31dea9432b6b83470d7b4594a3f24fccbd60d78a2e92a5e441339a89",
            "salt": "c782d6aff7fac03173335ba42d6428ff7f67140e24f10cccd50d97275e55baaa",
            "enc_entropy": "eb614567ea07d21b2df912462e375466d169c35fc93f8b5d2947c14580c5d0897f2fc13c4631ca4a1c264725523fc3acf2618e6c3957939b807ffbf1bff637d4899cfd75f4ea6d20f8a9774e7c5f13d1",
            "entropy_nonce": "ba7e99f7e02fafc54f6118a9",
            "enc_phrase": "8ae34ee2e87d80f1ef708a3025cd717e048522a0814529f5d27e04dad5b5d25628e80c5c022ed0bd2818348dca74729ec86e7d5537313c15079c305e9c3b982a518c9b3f2b9d5f1ab0be7065d6577ef58083e3f77d79a229b6216dbda961",
            "phrase_nonce": "737a285244c779159a3904dd",
            "accounts_map": {
                "4ebe5acc31dea9432b6b83470d7b4594a3f24fccbd60d78a2e92a5e441339a89": {
                    "name": "shrek",
                    "account_id": 0
                },
                "4d5653ed69caaa8e0417d952728bd5dc99a6d53510328a059e3584450a6a0359": {
                    "account_id": 2
                },
                "76fadb08e46bfeb71e63236a8bba9b2ce1f5025ea618837be24ead51ae7451fa": {
                    "account_id": 1
                }
            }
        }
    }
}"#;
        let mut loaded = DerivedKeySigner::new();
        loaded.load_state(json).unwrap();
    }
}
