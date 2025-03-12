use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Read;

use anyhow::Result;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
use rand::Rng;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

use nekoton_utils::*;

use super::mnemonic::*;
use super::{
    default_key_name, extend_with_signature_id, Password, PasswordCache, PasswordCacheTransaction,
    PubKey, SharedSecret, SignatureId, Signer as StoreSigner, SignerContext, SignerEntry,
    SignerStorage,
};

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

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
impl StoreSigner for EncryptedKeySigner {
    type CreateKeyInput = EncryptedKeyCreateInput;
    type ExportSeedInput = EncryptedKeyPassword;
    type ExportSeedOutput = EncryptedKeyExportSeedOutput;
    type ExportKeypairInput = EncryptedKeyPassword;
    type ExportKeypairOutput = Keypair;
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
        let name = key.inner.name.clone();
        self.keys.insert(public_key.to_bytes(), key);

        password.proceed();

        Ok(SignerEntry {
            name,
            public_key,
            master_key: public_key,
            account_id: input.mnemonic_type.account_id(),
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

    async fn export_seed(
        &self,
        ctx: SignerContext<'_>,
        input: Self::ExportSeedInput,
    ) -> Result<Self::ExportSeedOutput> {
        let key = self.get_key(&input.public_key)?;
        let password = ctx
            .password_cache
            .process_password(input.public_key.to_bytes(), input.password)?;

        let phrase = key.get_mnemonic(password.as_ref())?;

        password.proceed();
        Ok(Self::ExportSeedOutput {
            phrase,
            mnemonic_type: key.mnemonic_type(),
        })
    }

    async fn export_keypair(
        &self,
        ctx: SignerContext<'_>,
        input: Self::ExportKeypairInput,
    ) -> Result<Self::ExportKeypairOutput> {
        let key = self.get_key(&input.public_key)?;
        let password = ctx
            .password_cache
            .process_password(input.public_key.to_bytes(), input.password)?;

        let keypair = key.get_key_pair(password.as_ref())?;

        password.proceed();
        Ok(keypair)
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
        signature_id: Option<SignatureId>,
        input: Self::SignInput,
    ) -> Result<[u8; 64]> {
        let key = self.get_key(&input.public_key)?;

        let password = ctx
            .password_cache
            .process_password(input.public_key.to_bytes(), input.password)?;

        let signature = key.sign(data, signature_id, password.as_ref())?;

        password.proceed();
        Ok(signature)
    }
}

#[cfg_attr(not(feature = "non_threadsafe"), async_trait::async_trait)]
#[cfg_attr(feature = "non_threadsafe", async_trait::async_trait(?Send))]
impl SignerStorage for EncryptedKeySigner {
    fn load_state(&mut self, data: &str) -> Result<()> {
        let data = serde_json::from_str::<Vec<(String, String)>>(data)?;

        self.keys = data
            .into_iter()
            .map(|(public_key, data)| {
                let public_key = hex::decode(public_key)?
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
    pub name: Option<String>,
    pub phrase: SecUtf8,
    pub mnemonic_type: MnemonicType,
    pub password: Password,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyPassword {
    #[serde(with = "serde_public_key")]
    pub public_key: PublicKey,
    pub password: Password,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedKeyExportSeedOutput {
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
        name: Option<String>,
    ) -> Result<(Self, PasswordCacheTransaction<'_>)> {
        let rng = &mut rand::thread_rng();

        // prepare nonce
        let private_key_nonce = Nonce::from(rng.gen::<[u8; NONCE_LENGTH]>());
        let seed_phrase_nonce = Nonce::from(rng.gen::<[u8; NONCE_LENGTH]>());

        let mut salt = vec![0u8; CREDENTIAL_LEN];
        rng.fill(salt.as_mut_slice());

        let phrase = phrase.unsecure();
        let keypair = derive_from_phrase(phrase, mnemonic_type)?;

        let name = name.unwrap_or_else(|| default_key_name(keypair.public.as_bytes()));

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
        let rng = &mut rand::thread_rng();

        // prepare nonce
        let new_private_key_nonce = Nonce::from(rng.gen::<[u8; NONCE_LENGTH]>());
        let new_seed_phrase_nonce = Nonce::from(rng.gen::<[u8; NONCE_LENGTH]>());

        let mut new_salt = vec![0u8; CREDENTIAL_LEN];
        rng.fill(new_salt.as_mut_slice());

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
        signature_id: Option<SignatureId>,
        password: &str,
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]> {
        self.inner.sign(data, signature_id, password)
    }

    pub fn compute_shared_keys(
        &self,
        public_keys: &[PublicKey],
        password: &str,
    ) -> Result<Vec<SharedSecret>> {
        self.inner.compute_shared_keys(public_keys, password)
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
        signature_id: Option<SignatureId>,
        password: &str,
    ) -> Result<[u8; ed25519_dalek::SIGNATURE_LENGTH]> {
        let secret = self.decrypt_secret(password)?;
        let pair = Keypair {
            secret,
            public: self.pubkey,
        };
        let data = extend_with_signature_id(data, signature_id);
        Ok(pair.sign(&data).to_bytes())
    }

    pub fn compute_shared_keys(
        &self,
        public_keys: &[PublicKey],
        password: &str,
    ) -> Result<Vec<SharedSecret>> {
        let secret = self.decrypt_secret(password)?;

        Ok(public_keys
            .iter()
            .map(|public_key| {
                let secret = super::x25519::compute_shared(&secret, public_key);
                SharedSecret {
                    source_public_key: self.pubkey,
                    recipient_public_key: *public_key,
                    secret,
                }
            })
            .collect())
    }

    fn decrypt_secret(&self, password: &str) -> Result<ed25519_dalek::SecretKey> {
        let key = symmetric_key_from_password(password, &self.salt);
        let decrypter = ChaCha20Poly1305::new(&key);

        let bytes = decrypt_secure(
            &decrypter,
            &self.private_key_nonce,
            &self.encrypted_private_key,
        )?;

        let secret = SecretKey::from_bytes(bytes.unsecure())
            .map_err(|_| EncryptedKeyError::InvalidPrivateKey)?;

        Ok(secret)
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
    use std::time::Duration;

    use super::*;
    use crate::crypto::PasswordCacheBehavior;

    const TEST_PASSWORD: &str = "123";
    const TEST_MNEMONIC: &str = "canyon stage apple useful bench lazy grass enact canvas like figure help pave reopen betray exotic nose fetch wagon senior acid across salon alley";

    #[test]
    fn test_init() {
        let cache = PasswordCache::new();

        let password = Password::Explicit {
            password: SecUtf8::from(TEST_PASSWORD),
            cache_behavior: Default::default(),
        };
        EncryptedKey::new(
            &cache,
            password,
            MnemonicType::Legacy,
            TEST_MNEMONIC.into(),
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
        let (signer, _) = EncryptedKey::new(
            &cache,
            password,
            MnemonicType::Legacy,
            TEST_MNEMONIC.into(),
            Some("Test".to_owned()),
        )
        .unwrap();

        assert!(!signer.as_json().is_empty());
        let result = signer.sign(b"lol", None, "lol");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn load_old() {
        let json = r#"[
    [
        "122a6ca3f3785aeab4d2944cb5c49cf30efca1cf8f818faa8a8e7a17593751e0",
        "{\"mnemonic_type\":{\"Bip39\":{\"account_id\":0,\"network\":\"ever\",\"entropy\":\"bits128\"}},\"pubkey\":\"122a6ca3f3785aeab4d2944cb5c49cf30efca1cf8f818faa8a8e7a17593751e0\",\"encrypted_private_key\":\"7a714b8e92a9ef54c5da539141817018be4846fcf8a964e833712b39d560f50ec67dbde7c1a695fcb9303ef5c2002c70\",\"private_key_nonce\":\"1abc471cb49672d8ada0bed8\",\"encrypted_seed_phrase\":\"db7d9e170734990bff07e98758122aeb47d617393e12e761a69f384825b1b7423d991fed2ffa14e34cb31a26ba84e6ff3e688662655f401a6d9dd22b281a2be70ebab5f170ceb9a69c4770433aff5125cd7d35b5e6cc8a5dc0e3458ee9362cb5a3f50ac32be824171118cf802b5322e86a08ad8c9ead4b9f3afe549305107097960807d9c9b440ddc5b1fb8df0a0d97f9697a0c206accccd3d1795b524683bc0d7ac\",\"seed_phrase_nonce\":\"63d7a96bd2e8bd824f01a330\",\"salt\":\"b3ccb59480f3d4d6d6725b8f70bfaf520476cfa246bb50723f55a14535158358\"}"
    ],
    [
        "ef9ddfa972f424124033519c0190200d7e0f7964a637ebb131d1b0f999e02181",
        "{\"name\":\"史萊克的模因\",\"mnemonic_type\":{\"Bip39\":{\"account_id\":2,\"network\":\"ever\",\"entropy\":\"bits128\"}},\"pubkey\":\"ef9ddfa972f424124033519c0190200d7e0f7964a637ebb131d1b0f999e02181\",\"encrypted_private_key\":\"5397c31290043841221ce797ad9c7dbed21dd460ed937d3d988fd6a26e371ae7d5a717018a91ed5ab1db3e9516e53782\",\"private_key_nonce\":\"818dc748e3bf30b4f9dfe8c9\",\"encrypted_seed_phrase\":\"3ed4d10cee5034f1a09e8758a6f9cca4918399f9884c4e7607f8e9ce44cd7dad5e6daa8f71ca2522eac64c820b4d1b4b012400252c8a3dedbf19d4026dcdf4c02bec654190b686bfc9949daa884679ef47b435cc419ce0b2b677b81a7068da1bd5cfcc4f7dc1c772c653fede224eb94608b420045abf11eef94ea044bd75cbd86be5dbb1e45a891ec241f281970a498fab3153591d9e6abf18e368ac46ef1b6b9f46\",\"seed_phrase_nonce\":\"c0c964e2bf869cccbb8bc019\",\"salt\":\"c9f141e6516f40ea0d8879cc1149b8e489e1c39325d3f79ced4cf1ec17affd81\"}"
    ],
    [
        "93bcfd9fb026ecd897f33b2e224ed311c6332f0dadad1c1ddd32b94282f67190",
        "{\"mnemonic_type\":{\"Bip39\":{\"account_id\":0,\"network\":\"ever\",\"entropy\":\"bits128\"}},\"pubkey\":\"93bcfd9fb026ecd897f33b2e224ed311c6332f0dadad1c1ddd32b94282f67190\",\"encrypted_private_key\":\"518d6158968995a815f022bf5d0f9ada40c3d779454d54abb7a17e32b5a83a9f6ca57756142515b8fc968f87a1bceef7\",\"private_key_nonce\":\"0eaa9fcda666b7715c41b56b\",\"encrypted_seed_phrase\":\"f4e394d118230a8acb8af95b126fbf2a62fd764c24be9627f2bc2cb6d2aa48ba6694ecbac7cdf5317f42062acb8bb4645381d2c0ae63dd0ed577001743de96bec8f5968e516e585153d264b0d48132ead1daea9dd0bd68fb49263c3cd92df74a358f1611e92905ac3dc1f1105b743c07a9e2e7cb33344d1e3e3d6cf072a43ecbd771662e03ff61f4613015a2fc0298bbdbe9de87051d2e76ef01edfb25316d0f5131\",\"seed_phrase_nonce\":\"6266222cb4fd6bebf2b3b67e\",\"salt\":\"d3a0e42f386cbbc332d8d873b3e80ed0cde2ee9c16804f8866c0901493f2b6a5\"}"
    ]
]"#;
        let mut key = EncryptedKeySigner::new();
        key.load_state(json).unwrap();
        assert!(!key.store_state().is_empty());
    }

    #[tokio::test]
    async fn store_load() {
        let cache = PasswordCache::new();
        let ctx = SignerContext {
            password_cache: &cache,
        };

        let mut key = EncryptedKeySigner::new();

        let entry = key
            .add_key(
                ctx,
                EncryptedKeyCreateInput {
                    name: Some("from giver".to_string()),
                    phrase: TEST_MNEMONIC.into(),
                    mnemonic_type: MnemonicType::Bip39(Bip39MnemonicData::default()),
                    password: Password::Explicit {
                        password: SecUtf8::from("supasecret"),
                        cache_behavior: PasswordCacheBehavior::Store(Duration::from_secs(2)),
                    },
                },
            )
            .await
            .unwrap();

        key.export_seed(
            ctx,
            EncryptedKeyPassword {
                public_key: entry.public_key,
                password: Password::FromCache,
            },
        )
        .await
        .unwrap();

        let entry = key
            .add_key(
                ctx,
                EncryptedKeyCreateInput {
                    name: Some("new name. same mnemonic".to_string()),
                    phrase: TEST_MNEMONIC.into(),
                    mnemonic_type: MnemonicType::Bip39(Bip39MnemonicData::default()),
                    password: Password::Explicit {
                        password: SecUtf8::from("123123123123123123"),
                        cache_behavior: PasswordCacheBehavior::Store(Duration::from_secs(2)),
                    },
                },
            )
            .await
            .unwrap();

        key.export_seed(
            ctx,
            EncryptedKeyPassword {
                public_key: entry.public_key,
                password: Password::FromCache,
            },
        )
        .await
        .unwrap();

        key.add_key(
            ctx,
            EncryptedKeyCreateInput {
                name: Some("from giver".to_string()),
                phrase: TEST_MNEMONIC.into(),
                mnemonic_type: MnemonicType::Bip39(Bip39MnemonicData::default()),
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
                name: Some("all my money 🤑".to_string()),
                phrase: TEST_MNEMONIC.into(),
                mnemonic_type: MnemonicType::Bip39(Bip39MnemonicData {
                    account_id: 1,
                    network: Default::default(),
                    entropy: Default::default(),
                }),
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
                name: Some("史萊克的模因".to_string()),
                phrase: TEST_MNEMONIC.into(),
                mnemonic_type: MnemonicType::Bip39(Bip39MnemonicData {
                    account_id: 2,
                    network: Default::default(),
                    entropy: Default::default(),
                }),
                password: Password::Explicit {
                    password: SecUtf8::from("supasecret"),
                    cache_behavior: Default::default(),
                },
            },
        )
        .await
        .unwrap();

        let serialized = key.store_state();

        let mut loaded = EncryptedKeySigner::new();
        loaded.load_state(&serialized).unwrap();
        assert_eq!(loaded, key);
    }
}
