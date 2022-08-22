use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Read;

use anyhow::Result;
use async_trait::async_trait;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::Rng;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

use nekoton_utils::*;

use super::{default_key_name, PasswordCache, Signer, SignerContext, SignerEntry, SignerStorage};
use crate::crypto::mnemonic::*;
use crate::crypto::password_cache::*;
use crate::crypto::SharedSecret;

#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct SimpleSigner {
    keys: KeysMap,
}

type KeysMap = HashMap<[u8; 32], SimpleSignerEntry>;

impl SimpleSigner {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_key(&self, public_key: &PublicKey) -> Result<&SimpleSignerEntry> {
        match self.keys.get(public_key.as_bytes()) {
            Some(key) => Ok(key),
            None => Err(SimpleSignerError::KeyNotFound.into()),
        }
    }

    fn get_key_mut(&mut self, public_key: &PublicKey) -> Result<&mut SimpleSignerEntry> {
        match self.keys.get_mut(public_key.as_bytes()) {
            Some(key) => Ok(key),
            None => Err(SimpleSignerError::KeyNotFound.into()),
        }
    }
}

#[async_trait]
impl Signer for SimpleSigner {
    type CreateKeyInput = CreateKeyParams;
    type ExportKeyInput = KeyPassword;
    type ExportKeyOutput = KeyData;
    type GetPublicKeys = GetPublicKeysParams;
    type UpdateKeyInput = UpdateKeyParams;
    type SignInput = KeyPassword;

    async fn add_key(
        &mut self,
        ctx: SignerContext<'_>,
        input: Self::CreateKeyInput,
    ) -> Result<SignerEntry> {
        let account_id = match &input.data {
            KeyData::Phrase { account_id, .. } => *account_id,
            KeyData::Raw { .. } => 0,
        };
        let (key, password) =
            SimpleSignerEntry::new(ctx.password_cache, input.password, input.data, input.name)?;

        let public_key = key.pubkey;
        let name = key.name.clone();
        self.keys.insert(public_key.to_bytes(), key);

        password.proceed();

        Ok(SignerEntry {
            name,
            public_key,
            master_key: public_key,
            account_id,
        })
    }

    async fn update_key(
        &mut self,
        ctx: SignerContext<'_>,
        input: Self::UpdateKeyInput,
    ) -> Result<SignerEntry> {
        match input {
            Self::UpdateKeyInput::Rename { public_key, name } => {
                let key = self.get_key_mut(&public_key)?;
                key.name = name.clone();
                Ok(SignerEntry {
                    name,
                    public_key,
                    master_key: public_key,
                    account_id: key.account_id(),
                })
            }
            Self::UpdateKeyInput::ChangePassword {
                public_key,
                old_password,
                new_password,
            } => {
                let old_password = ctx
                    .password_cache
                    .process_password(public_key.to_bytes(), old_password)?;
                let new_password = ctx
                    .password_cache
                    .process_password(public_key.to_bytes(), new_password)?;

                let key = self.get_key_mut(&public_key)?;
                key.change_password(old_password.as_ref(), new_password.as_ref())?;

                new_password.proceed();

                Ok(SignerEntry {
                    name: key.name.clone(),
                    public_key,
                    master_key: public_key,
                    account_id: key.account_id(),
                })
            }
        }
    }

    async fn export_key(
        &self,
        ctx: SignerContext<'_>,
        input: Self::ExportKeyInput,
    ) -> Result<Self::ExportKeyOutput> {
        let key = self.get_key(&input.public_key)?;
        let password = ctx
            .password_cache
            .process_password(input.public_key.to_bytes(), input.password)?;

        let data = key.export_data(password.as_ref())?;

        password.proceed();
        Ok(data)
    }

    /// Does nothing useful, only exists for compatibility with other signers
    async fn get_public_keys(
        &self,
        _: SignerContext<'_>,
        input: Self::GetPublicKeys,
    ) -> Result<Vec<PublicKey>> {
        let _key = self.get_key(&input.public_key)?;
        Ok(vec![input.public_key])
    }

    async fn compute_shared_secrets(
        &self,
        ctx: SignerContext<'_>,
        public_keys: &[PublicKey],
        input: Self::SignInput,
    ) -> Result<Vec<SharedSecret>> {
        let key = self.get_key(&input.public_key)?;

        let password = ctx
            .password_cache
            .process_password(input.public_key.to_bytes(), input.password)?;

        let shared_keys = key.compute_shared_keys(public_keys, password.as_ref())?;

        password.proceed();
        Ok(shared_keys)
    }

    async fn sign(
        &self,
        ctx: SignerContext<'_>,
        data: &[u8],
        input: Self::SignInput,
    ) -> Result<[u8; 64]> {
        let key = self.get_key(&input.public_key)?;

        let password = ctx
            .password_cache
            .process_password(input.public_key.to_bytes(), input.password)?;

        let signature = key.sign(data, password.as_ref())?;

        password.proceed();
        Ok(signature)
    }
}

#[async_trait]
impl SignerStorage for SimpleSigner {
    fn load_state(&mut self, data: &str) -> Result<()> {
        let data = serde_json::from_str::<Vec<(String, String)>>(data)?;

        self.keys = data
            .into_iter()
            .map(|(public_key, data)| {
                let public_key = hex::decode(&public_key)?
                    .try_into()
                    .map_err(|_| SimpleSignerError::InvalidPublicKey)?;
                let data = SimpleSignerEntry::from_reader(&mut data.as_bytes())?;
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
                name: key.name.clone(),
                public_key: key.pubkey,
                master_key: key.pubkey,
                account_id: key.account_id(),
            })
            .collect()
    }

    async fn remove_key(&mut self, public_key: &PublicKey) -> Option<SignerEntry> {
        let entry = self.keys.remove(public_key.as_bytes())?;
        Some(SignerEntry {
            account_id: entry.account_id(),
            name: entry.name,
            public_key: entry.pubkey,
            master_key: entry.pubkey,
        })
    }

    async fn clear(&mut self) {
        self.keys.clear();
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateKeyParams {
    pub name: Option<String>,
    pub data: KeyData,
    pub password: Password,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum KeyData {
    Phrase {
        phrase: SecUtf8,
        mnemonic_type: MnemonicType,
        account_id: u16,
    },
    Raw {
        #[serde(with = "serde_secret_key")]
        secret_key: SecretKey,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPassword {
    #[serde(with = "serde_public_key")]
    pub public_key: PublicKey,
    pub password: Password,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetPublicKeysParams {
    #[serde(with = "serde_public_key")]
    pub public_key: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum UpdateKeyParams {
    Rename {
        #[serde(with = "serde_public_key")]
        public_key: PublicKey,
        name: String,
    },
    ChangePassword {
        #[serde(with = "serde_public_key")]
        public_key: PublicKey,
        old_password: Password,
        new_password: Password,
    },
}

const CREDENTIAL_LEN: usize = 32;

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct SimpleSignerEntry {
    name: String,

    #[serde(with = "serde_public_key")]
    pubkey: PublicKey,

    #[serde(with = "serde_bytes")]
    encrypted_private_key: Vec<u8>,
    #[serde(with = "serde_nonce")]
    private_key_nonce: Nonce,

    #[serde(flatten)]
    encrypted_seed: Option<EncryptedSeedPhrase>,

    #[serde(with = "serde_bytes")]
    salt: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct EncryptedSeedPhrase {
    mnemonic_type: MnemonicType,
    #[serde(with = "serde_bytes")]
    encrypted_seed_phrase: Vec<u8>,
    #[serde(with = "serde_nonce")]
    seed_phrase_nonce: Nonce,
    #[serde(default)]
    account_id: u16,
}

impl SimpleSignerEntry {
    pub fn new(
        password_cache: &'_ PasswordCache,
        password: Password,
        data: KeyData,
        name: Option<String>,
    ) -> Result<(Self, PasswordCacheTransaction<'_>)> {
        let rng = &mut rand::thread_rng();

        let mut salt = vec![0u8; CREDENTIAL_LEN];
        rng.fill(salt.as_mut_slice());

        let make_encryptor = |pubkey: &PublicKey| {
            let password = password_cache.process_password(pubkey.to_bytes(), password)?;
            Ok::<_, anyhow::Error>((
                ChaCha20Poly1305::new(&symmetric_key_from_password(password.as_ref(), &salt)),
                password,
            ))
        };

        let (keypair, encryptor, password, encrypted_seed) = match data {
            KeyData::Phrase {
                phrase,
                mnemonic_type,
                account_id,
            } => {
                let phrase = phrase.unsecure();
                let keypair = derive_from_phrase(phrase, mnemonic_type, account_id)?;

                let (encryptor, password) = make_encryptor(&keypair.public)?;

                let seed_phrase_nonce = Nonce::from(rng.gen::<[u8; NONCE_LENGTH]>());
                let encrypted_seed = EncryptedSeedPhrase {
                    mnemonic_type,
                    encrypted_seed_phrase: encrypt(
                        &encryptor,
                        &seed_phrase_nonce,
                        phrase.as_ref(),
                    )?,
                    seed_phrase_nonce,
                    account_id,
                };

                (keypair, encryptor, password, Some(encrypted_seed))
            }
            KeyData::Raw { secret_key } => {
                let keypair = Keypair {
                    public: PublicKey::from(&secret_key),
                    secret: secret_key,
                };
                let (encryptor, password) = make_encryptor(&keypair.public)?;
                (keypair, encryptor, password, None)
            }
        };

        let name = name.unwrap_or_else(|| default_key_name(keypair.public.as_bytes()));

        let pubkey = keypair.public;

        // encrypt private key
        let private_key_nonce = Nonce::from(rng.gen::<[u8; NONCE_LENGTH]>());
        let encrypted_private_key =
            encrypt(&encryptor, &private_key_nonce, keypair.secret.as_ref())?;

        Ok((
            Self {
                name,
                pubkey,
                encrypted_private_key,
                private_key_nonce,
                encrypted_seed,
                salt,
            },
            password,
        ))
    }

    pub fn export_data(&self, password: &str) -> Result<KeyData, SimpleSignerError> {
        let password = symmetric_key_from_password(password, &self.salt);
        let dec = ChaCha20Poly1305::new(&password);

        match &self.encrypted_seed {
            Some(encrypted_seed) => {
                let phrase = decrypt_secure_str(
                    &dec,
                    &encrypted_seed.seed_phrase_nonce,
                    &encrypted_seed.encrypted_seed_phrase,
                )
                .map_err(|_| SimpleSignerError::FailedToDecryptData)?;

                Ok(KeyData::Phrase {
                    phrase,
                    mnemonic_type: encrypted_seed.mnemonic_type,
                    account_id: encrypted_seed.account_id,
                })
            }
            None => {
                let secret =
                    decrypt_secure(&dec, &self.private_key_nonce, &self.encrypted_private_key)
                        .map_err(|_| SimpleSignerError::FailedToDecryptData)?;
                Ok(KeyData::Raw {
                    secret_key: SecretKey::from_bytes(secret.unsecure())
                        .map_err(|_| SimpleSignerError::InvalidPrivateKey)?,
                })
            }
        }
    }

    pub fn get_key_pair(&self, password: &str) -> Result<Keypair, SimpleSignerError> {
        let password = symmetric_key_from_password(password, &self.salt);
        decrypt_key_pair(
            &self.encrypted_private_key,
            &password,
            &self.private_key_nonce,
        )
    }

    pub fn from_reader<T>(reader: T) -> Result<Self>
    where
        T: Read,
    {
        serde_json::from_reader(reader).map_err(From::from)
    }

    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        let rng = &mut rand::thread_rng();

        // prepare nonce
        let new_private_key_nonce = Nonce::from(rng.gen::<[u8; NONCE_LENGTH]>());
        let new_seed_phrase_nonce = Nonce::from(rng.gen::<[u8; NONCE_LENGTH]>());

        let mut new_salt = vec![0u8; CREDENTIAL_LEN];
        rng.fill(new_salt.as_mut_slice());

        // prepare encryptor/decrypter pair
        let old_key = symmetric_key_from_password(old_password, &self.salt);
        let new_key = symmetric_key_from_password(new_password, &new_salt);

        let decrypter = ChaCha20Poly1305::new(&old_key);
        let encryptor = ChaCha20Poly1305::new(&new_key);

        // reencrypt key pair
        let new_encrypted_private_key = {
            let key_pair = decrypt_key_pair(
                &self.encrypted_private_key,
                &old_key,
                &self.private_key_nonce,
            )?;
            encrypt(&encryptor, &new_private_key_nonce, key_pair.secret.as_ref())?
        };

        // reencrypt seed phrase
        if let Some(encrypted_seed) = &mut self.encrypted_seed {
            let seed_phrase = decrypt_secure(
                &decrypter,
                &encrypted_seed.seed_phrase_nonce,
                &encrypted_seed.encrypted_seed_phrase,
            )?;

            let encrypted_seed_phrase =
                encrypt(&encryptor, &new_seed_phrase_nonce, seed_phrase.unsecure())?;

            // NOTE: Update after all possible error paths
            encrypted_seed.encrypted_seed_phrase = encrypted_seed_phrase;
        }

        // save new data
        self.salt = new_salt;

        self.encrypted_private_key = new_encrypted_private_key;
        self.private_key_nonce = new_private_key_nonce;

        // done
        Ok(())
    }

    pub fn sign(
        &self,
        data: &[u8],
        password: &str,
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]> {
        let secret = self.decrypt_secret(password)?;
        let pair = Keypair {
            secret,
            public: self.pubkey,
        };
        Ok(ed25519_dalek::Signer::sign(&pair, data).to_bytes())
    }

    pub fn compute_shared_keys(
        &self,
        public_keys: &[PublicKey],
        password: &str,
    ) -> Result<Vec<SharedSecret>> {
        let secret = self.decrypt_secret(password)?;
        let keypair = Keypair {
            public: PublicKey::from(&secret),
            secret,
        };

        Ok(public_keys
            .iter()
            .map(|public_key| SharedSecret::x25519(&keypair, public_key))
            .collect())
    }

    pub fn account_id(&self) -> u16 {
        match &self.encrypted_seed {
            Some(seed) => seed.account_id,
            None => 0,
        }
    }

    pub fn as_json(&self) -> String {
        serde_json::to_string(self).trust_me()
    }

    fn decrypt_secret(&self, password: &str) -> Result<SecretKey> {
        let key = symmetric_key_from_password(password, &*self.salt);
        let decrypter = ChaCha20Poly1305::new(&key);

        let bytes = decrypt_secure(
            &decrypter,
            &self.private_key_nonce,
            &self.encrypted_private_key,
        )?;

        let secret = SecretKey::from_bytes(bytes.unsecure())
            .map_err(|_| SimpleSignerError::InvalidPrivateKey)?;

        Ok(secret)
    }
}

impl std::fmt::Debug for SimpleSignerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.pubkey)
    }
}

impl<'de> Deserialize<'de> for SimpleSignerEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StoredSimpleSignerEntry {
            #[serde(default)]
            name: Option<String>,
            #[serde(with = "serde_public_key")]
            pubkey: PublicKey,
            #[serde(with = "serde_bytes")]
            encrypted_private_key: Vec<u8>,
            #[serde(with = "serde_nonce")]
            private_key_nonce: Nonce,
            #[serde(flatten)]
            encrypted_seed: Option<EncryptedSeedPhrase>,
            #[serde(with = "serde_bytes")]
            salt: Vec<u8>,
        }

        let data: StoredSimpleSignerEntry = Deserialize::deserialize(deserializer)?;
        let name = match data.name {
            Some(name) => name,
            None => default_key_name(data.pubkey.as_bytes()),
        };

        Ok(SimpleSignerEntry {
            name,
            pubkey: data.pubkey,
            encrypted_private_key: data.encrypted_private_key,
            private_key_nonce: data.private_key_nonce,
            encrypted_seed: data.encrypted_seed,
            salt: data.salt,
        })
    }
}

fn decrypt_key_pair(
    encrypted_key: &[u8],
    key: &Key,
    nonce: &Nonce,
) -> Result<Keypair, SimpleSignerError> {
    let decrypter = ChaCha20Poly1305::new(key);
    let bytes = decrypt(&decrypter, nonce, encrypted_key)?;
    let secret = SecretKey::from_bytes(&bytes).map_err(|_| SimpleSignerError::InvalidPrivateKey)?;
    let public = PublicKey::from(&secret);
    Ok(Keypair { secret, public })
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum SimpleSignerError {
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Failed to decrypt data")]
    FailedToDecryptData,
    #[error("Failed to encrypt data")]
    FailedToEncryptData,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Invalid public key")]
    InvalidPublicKey,
}

impl From<SymmetricCryptoError> for SimpleSignerError {
    fn from(a: SymmetricCryptoError) -> Self {
        match a {
            SymmetricCryptoError::FailedToDecryptData => Self::FailedToDecryptData,
            SymmetricCryptoError::FailedToEncryptData => Self::FailedToEncryptData,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const TEST_PASSWORD: &str = "123";
    const TEST_MNEMONIC: &str = "canyon stage apple useful bench lazy grass enact canvas like figure help pave reopen betray exotic nose fetch wagon senior acid across salon alley";

    #[test]
    fn test_init() {
        let cache = PasswordCache::new();

        let password = Password::Explicit {
            password: SecUtf8::from(TEST_PASSWORD),
            cache_behavior: Default::default(),
        };
        SimpleSignerEntry::new(
            &cache,
            password,
            KeyData::Phrase {
                phrase: TEST_MNEMONIC.into(),
                mnemonic_type: MnemonicType::Legacy,
                account_id: 0,
            },
            Some("Test".to_owned()),
        )
        .unwrap();
    }

    #[test]
    fn test_bad_password() {
        let cache = PasswordCache::new();

        let password = Password::Explicit {
            password: SecUtf8::from(TEST_PASSWORD),
            cache_behavior: Default::default(),
        };
        let (signer, _) = SimpleSignerEntry::new(
            &cache,
            password,
            KeyData::Phrase {
                phrase: TEST_MNEMONIC.into(),
                mnemonic_type: MnemonicType::Legacy,
                account_id: 0,
            },
            Some("Test".to_owned()),
        )
        .unwrap();

        assert!(!signer.as_json().is_empty());
        let result = signer.sign(b"lol", "lol");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn load_old() {
        let json = r#"[
    [
        "122a6ca3f3785aeab4d2944cb5c49cf30efca1cf8f818faa8a8e7a17593751e0",
        "{\"mnemonic_type\":{\"Labs\":1},\"pubkey\":\"122a6ca3f3785aeab4d2944cb5c49cf30efca1cf8f818faa8a8e7a17593751e0\",\"encrypted_private_key\":\"7a714b8e92a9ef54c5da539141817018be4846fcf8a964e833712b39d560f50ec67dbde7c1a695fcb9303ef5c2002c70\",\"private_key_nonce\":\"1abc471cb49672d8ada0bed8\",\"encrypted_seed_phrase\":\"db7d9e170734990bff07e98758122aeb47d617393e12e761a69f384825b1b7423d991fed2ffa14e34cb31a26ba84e6ff3e688662655f401a6d9dd22b281a2be70ebab5f170ceb9a69c4770433aff5125cd7d35b5e6cc8a5dc0e3458ee9362cb5a3f50ac32be824171118cf802b5322e86a08ad8c9ead4b9f3afe549305107097960807d9c9b440ddc5b1fb8df0a0d97f9697a0c206accccd3d1795b524683bc0d7ac\",\"seed_phrase_nonce\":\"63d7a96bd2e8bd824f01a330\",\"salt\":\"b3ccb59480f3d4d6d6725b8f70bfaf520476cfa246bb50723f55a14535158358\"}"
    ],
    [
        "ef9ddfa972f424124033519c0190200d7e0f7964a637ebb131d1b0f999e02181",
        "{\"name\":\"史萊克的模因\",\"mnemonic_type\":{\"Labs\":2},\"pubkey\":\"ef9ddfa972f424124033519c0190200d7e0f7964a637ebb131d1b0f999e02181\",\"encrypted_private_key\":\"5397c31290043841221ce797ad9c7dbed21dd460ed937d3d988fd6a26e371ae7d5a717018a91ed5ab1db3e9516e53782\",\"private_key_nonce\":\"818dc748e3bf30b4f9dfe8c9\",\"encrypted_seed_phrase\":\"3ed4d10cee5034f1a09e8758a6f9cca4918399f9884c4e7607f8e9ce44cd7dad5e6daa8f71ca2522eac64c820b4d1b4b012400252c8a3dedbf19d4026dcdf4c02bec654190b686bfc9949daa884679ef47b435cc419ce0b2b677b81a7068da1bd5cfcc4f7dc1c772c653fede224eb94608b420045abf11eef94ea044bd75cbd86be5dbb1e45a891ec241f281970a498fab3153591d9e6abf18e368ac46ef1b6b9f46\",\"seed_phrase_nonce\":\"c0c964e2bf869cccbb8bc019\",\"salt\":\"c9f141e6516f40ea0d8879cc1149b8e489e1c39325d3f79ced4cf1ec17affd81\"}"
    ],
    [
        "93bcfd9fb026ecd897f33b2e224ed311c6332f0dadad1c1ddd32b94282f67190",
        "{\"mnemonic_type\":{\"Labs\":0},\"pubkey\":\"93bcfd9fb026ecd897f33b2e224ed311c6332f0dadad1c1ddd32b94282f67190\",\"encrypted_private_key\":\"518d6158968995a815f022bf5d0f9ada40c3d779454d54abb7a17e32b5a83a9f6ca57756142515b8fc968f87a1bceef7\",\"private_key_nonce\":\"0eaa9fcda666b7715c41b56b\",\"encrypted_seed_phrase\":\"f4e394d118230a8acb8af95b126fbf2a62fd764c24be9627f2bc2cb6d2aa48ba6694ecbac7cdf5317f42062acb8bb4645381d2c0ae63dd0ed577001743de96bec8f5968e516e585153d264b0d48132ead1daea9dd0bd68fb49263c3cd92df74a358f1611e92905ac3dc1f1105b743c07a9e2e7cb33344d1e3e3d6cf072a43ecbd771662e03ff61f4613015a2fc0298bbdbe9de87051d2e76ef01edfb25316d0f5131\",\"seed_phrase_nonce\":\"6266222cb4fd6bebf2b3b67e\",\"salt\":\"d3a0e42f386cbbc332d8d873b3e80ed0cde2ee9c16804f8866c0901493f2b6a5\"}"
    ]
]"#;
        let mut key = SimpleSigner::new();
        key.load_state(json).unwrap();
        assert!(!key.store_state().is_empty());
    }

    #[tokio::test]
    async fn store_load() {
        let cache = PasswordCache::new();
        let ctx = SignerContext {
            password_cache: &cache,
        };

        let mut key = SimpleSigner::new();

        let entry = key
            .add_key(
                ctx,
                CreateKeyParams {
                    name: Some("from giver".to_string()),
                    data: KeyData::Phrase {
                        phrase: TEST_MNEMONIC.into(),
                        mnemonic_type: MnemonicType::Bip39,
                        account_id: 0,
                    },
                    password: Password::Explicit {
                        password: SecUtf8::from("supasecret"),
                        cache_behavior: PasswordCacheBehavior::Store(Duration::from_secs(2)),
                    },
                },
            )
            .await
            .unwrap();

        key.export_key(
            ctx,
            KeyPassword {
                public_key: entry.public_key,
                password: Password::FromCache,
            },
        )
        .await
        .unwrap();

        let entry = key
            .add_key(
                ctx,
                CreateKeyParams {
                    name: Some("new name. same mnemonic".to_string()),
                    data: KeyData::Phrase {
                        phrase: TEST_MNEMONIC.into(),
                        mnemonic_type: MnemonicType::Bip39,
                        account_id: 0,
                    },
                    password: Password::Explicit {
                        password: SecUtf8::from("123123123123123123"),
                        cache_behavior: PasswordCacheBehavior::Store(Duration::from_secs(2)),
                    },
                },
            )
            .await
            .unwrap();

        key.export_key(
            ctx,
            KeyPassword {
                public_key: entry.public_key,
                password: Password::FromCache,
            },
        )
        .await
        .unwrap();

        key.add_key(
            ctx,
            CreateKeyParams {
                name: Some("from giver".to_string()),
                data: KeyData::Phrase {
                    phrase: TEST_MNEMONIC.into(),
                    mnemonic_type: MnemonicType::Bip39,
                    account_id: 0,
                },
                password: Password::Explicit {
                    password: SecUtf8::from("supasecret"),
                    cache_behavior: Default::default(),
                },
            },
        )
        .await
        .unwrap();

        key.add_key(
            ctx,
            CreateKeyParams {
                name: Some("all my money 🤑".to_string()),
                data: KeyData::Phrase {
                    phrase: TEST_MNEMONIC.into(),
                    mnemonic_type: MnemonicType::Bip39,
                    account_id: 1,
                },
                password: Password::Explicit {
                    password: SecUtf8::from("supasecret"),
                    cache_behavior: Default::default(),
                },
            },
        )
        .await
        .unwrap();

        key.add_key(
            ctx,
            CreateKeyParams {
                name: Some("史萊克的模因".to_string()),
                data: KeyData::Phrase {
                    phrase: TEST_MNEMONIC.into(),
                    mnemonic_type: MnemonicType::Bip39,
                    account_id: 2,
                },
                password: Password::Explicit {
                    password: SecUtf8::from("supasecret"),
                    cache_behavior: Default::default(),
                },
            },
        )
        .await
        .unwrap();

        let serialized = key.store_state();

        let mut loaded = SimpleSigner::new();
        loaded.load_state(&serialized).unwrap();
        assert_eq!(loaded, key);
    }
}
