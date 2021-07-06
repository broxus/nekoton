use std::collections::hash_map::{self, HashMap};
use std::convert::TryInto;
use std::io::Read;

use anyhow::Result;
use async_trait::async_trait;
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
use ring::digest;
use ring::rand::SecureRandom;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

use super::mnemonic::*;
use super::symmetric::*;
use super::{default_key_name, PubKey};
use crate::crypto::{
    Password, PasswordCache, PasswordCacheTransaction, Signer as StoreSigner, SignerContext,
    SignerEntry, SignerStorage,
};
use crate::utils::*;

#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct EncryptedKeySigner {
    keys: KeysMap,
}

type KeysMap = HashMap<PubKey, EncryptedKey>;

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
    type GetPublicKeys = EncryptedKeyGetPublicKeys;
    type UpdateKeyInput = EncryptedKeyUpdateParams;
    type SignInput = EncryptedKeyPassword;

    async fn add_key(
        &mut self,
        ctx: SignerContext<'_>,
        input: Self::CreateKeyInput,
    ) -> Result<SignerEntry> {
        let (key, password) = EncryptedKey::new(
            ctx.password_cache,
            input.password,
            input.mnemonic_type,
            input.phrase,
            input.name,
        )?;

        let public_key = *key.public_key();

        match self.keys.entry(public_key.to_bytes()) {
            hash_map::Entry::Vacant(entry) => {
                let name = key.inner.name.clone();
                entry.insert(key);

                password.proceed();
                Ok(SignerEntry {
                    name,
                    public_key,
                    master_key: public_key,
                    account_id: input.mnemonic_type.account_id(),
                })
            }
            hash_map::Entry::Occupied(_) => return Err(EncryptedKeyError::KeyAlreadyExists.into()),
        }
    }

    async fn update_key(
        &mut self,
        ctx: SignerContext<'_>,
        input: Self::UpdateKeyInput,
    ) -> Result<SignerEntry> {
        match input {
            Self::UpdateKeyInput::Rename { public_key, name } => {
                let key = self.get_key_mut(&public_key)?;
                key.inner.name = name.clone();
                Ok(SignerEntry {
                    name,
                    public_key,
                    master_key: public_key,
                    account_id: key.mnemonic_type().account_id(),
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
                    name: key.inner.name.clone(),
                    public_key,
                    master_key: public_key,
                    account_id: key.mnemonic_type().account_id(),
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

        let phrase = key.get_mnemonic(password.as_ref())?;

        password.proceed();
        Ok(Self::ExportKeyOutput {
            phrase,
            mnemonic_type: key.mnemonic_type(),
        })
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
                name: key.inner.name.clone(),
                public_key: *key.public_key(),
                master_key: *key.public_key(),
                account_id: key.inner.mnemonic_type.account_id(),
            })
            .collect()
    }

    async fn remove_key(&mut self, public_key: &PublicKey) -> Option<SignerEntry> {
        let entry = self.keys.remove(public_key.as_bytes())?;
        Some(SignerEntry {
            name: entry.inner.name,
            public_key: entry.inner.pubkey,
            master_key: entry.inner.pubkey,
            account_id: entry.inner.mnemonic_type.account_id(),
        })
    }

    async fn clear(&mut self) {
        self.keys.clear();
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedKeyCreateInput {
    pub name: String,
    pub phrase: SecUtf8,
    pub mnemonic_type: MnemonicType,
    pub password: Password,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyPassword {
    #[serde(with = "crate::utils::serde_public_key")]
    pub public_key: PublicKey,
    pub password: Password,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedKeyExportOutput {
    pub phrase: SecUtf8,
    pub mnemonic_type: MnemonicType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EncryptedKeyGetPublicKeys {
    #[serde(with = "serde_public_key")]
    pub public_key: PublicKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum EncryptedKeyUpdateParams {
    Rename {
        #[serde(with = "crate::utils::serde_public_key")]
        public_key: PublicKey,
        name: String,
    },
    ChangePassword {
        #[serde(with = "crate::utils::serde_public_key")]
        public_key: PublicKey,
        old_password: Password,
        new_password: Password,
    },
}

const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedKey {
    inner: CryptoData,
}

impl EncryptedKey {
    pub fn new(
        password_cache: &'_ PasswordCache,
        password: Password,
        mnemonic_type: MnemonicType,
        phrase: SecUtf8,
        name: String,
    ) -> Result<(Self, PasswordCacheTransaction<'_>)> {
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

        let phrase = phrase.unsecure();
        let keypair = derive_from_phrase(phrase, mnemonic_type)?;

        let password = password_cache.process_password(keypair.public.to_bytes(), password)?;

        // prepare encryptor
        let encryptor =
            ChaCha20Poly1305::new(&symmetric_key_from_password(password.as_ref(), &salt));

        // encrypt private key
        let pubkey = keypair.public;
        let encrypted_private_key =
            encrypt(&encryptor, &private_key_nonce, keypair.secret.as_ref())?;

        // encrypt seed phrase
        let encrypted_seed_phrase = encrypt(&encryptor, &seed_phrase_nonce, phrase.as_ref())?;

        Ok((
            Self {
                inner: CryptoData {
                    name,
                    mnemonic_type,
                    pubkey,
                    encrypted_private_key,
                    private_key_nonce,
                    encrypted_seed_phrase,
                    seed_phrase_nonce,
                    salt,
                },
            },
            password,
        ))
    }

    pub fn get_mnemonic(&self, password: &str) -> Result<SecUtf8, EncryptedKeyError> {
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

    pub fn get_key_pair(&self, password: &str) -> Result<Keypair, EncryptedKeyError> {
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

    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
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

    pub fn sign(
        &self,
        data: &[u8],
        password: &str,
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]> {
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
#[derive(Serialize, Clone, Eq, PartialEq)]
struct CryptoData {
    name: String,

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
    pub fn sign(
        &self,
        data: &[u8],
        password: &str,
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]> {
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
        Ok(pair.sign(data).to_bytes())
    }
}

impl<'de> Deserialize<'de> for CryptoData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StoredCryptoData {
            #[serde(default)]
            name: Option<String>,
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

        let data = StoredCryptoData::deserialize(deserializer)?;
        let name = match data.name {
            Some(name) => name,
            None => default_key_name(data.pubkey.as_bytes()),
        };

        Ok(CryptoData {
            name,
            mnemonic_type: data.mnemonic_type,
            pubkey: data.pubkey,
            encrypted_private_key: data.encrypted_private_key,
            private_key_nonce: data.private_key_nonce,
            encrypted_seed_phrase: data.encrypted_seed_phrase,
            seed_phrase_nonce: data.seed_phrase_nonce,
            salt: data.salt,
        })
    }
}

fn decrypt_key_pair(
    encrypted_key: &[u8],
    key: &Key,
    nonce: &Nonce,
) -> Result<ed25519_dalek::Keypair, EncryptedKeyError> {
    let decrypter = ChaCha20Poly1305::new(key);
    let bytes = decrypt(&decrypter, nonce, encrypted_key)?;
    let secret = SecretKey::from_bytes(&bytes).map_err(|_| EncryptedKeyError::InvalidPrivateKey)?;
    let public = PublicKey::from(&secret);
    Ok(Keypair { secret, public })
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
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
mod tests {
    use super::*;

    const TEST_PASSWORD: &str = "123";
    const TEST_MNEMONIC: &str = "canyon stage apple useful bench lazy grass enact canvas like figure help pave reopen betray exotic nose fetch wagon senior acid across salon alley";

    #[test]
    fn test_init() {
        let cache = PasswordCache::new().unwrap();

        let password = Password::Explicit {
            password: SecUtf8::from(TEST_PASSWORD),
            cache_behavior: Default::default(),
        };
        EncryptedKey::new(
            &cache,
            password,
            MnemonicType::Legacy,
            TEST_MNEMONIC.into(),
            "Test".to_owned(),
        )
        .unwrap();
    }

    #[test]
    fn test_bad_password() {
        let cache = PasswordCache::new().unwrap();

        let password = Password::Explicit {
            password: SecUtf8::from(TEST_PASSWORD),
            cache_behavior: Default::default(),
        };
        let (signer, _) = EncryptedKey::new(
            &cache,
            password,
            MnemonicType::Legacy,
            TEST_MNEMONIC.into(),
            "Test".to_owned(),
        )
        .unwrap();

        println!("{}", signer.as_json());
        let result = signer.sign(b"lol", "lol".into());
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
        let mut key = EncryptedKeySigner::new();
        key.load_state(&json).unwrap();
        let serialized = key.store_state();
        println!("{}", serialized);
    }

    #[tokio::test]
    async fn store_load() {
        let cache = PasswordCache::new().unwrap();
        let ctx = SignerContext {
            password_cache: &cache,
        };

        let mut key = EncryptedKeySigner::new();

        key.add_key(
            ctx,
            EncryptedKeyCreateInput {
                name: "from giver".to_string(),
                phrase: TEST_MNEMONIC.into(),
                mnemonic_type: MnemonicType::Labs(0),
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
            EncryptedKeyCreateInput {
                name: "all my money 🤑".to_string(),
                phrase: TEST_MNEMONIC.into(),
                mnemonic_type: MnemonicType::Labs(1),
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
            EncryptedKeyCreateInput {
                name: "史萊克的模因".to_string(),
                phrase: TEST_MNEMONIC.into(),
                mnemonic_type: MnemonicType::Labs(2),
                password: Password::Explicit {
                    password: SecUtf8::from("supasecret"),
                    cache_behavior: Default::default(),
                },
            },
        )
        .await
        .unwrap();

        let serialized = key.store_state();
        println!("{}", serialized);

        let mut loaded = EncryptedKeySigner::new();
        loaded.load_state(&serialized).unwrap();
        assert_eq!(loaded, key);
    }
}
