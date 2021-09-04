use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use parking_lot::RwLock;
use ring::rand::SecureRandom;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

pub struct PasswordCache {
    state: RwLock<PasswordCacheState>,
}

impl PasswordCache {
    pub fn new() -> Result<Self> {
        Ok(Self {
            state: RwLock::new(PasswordCacheState {
                cipher: make_cipher()?,
                passwords: Default::default(),
            }),
        })
    }

    pub fn process_password(
        &'_ self,
        id: [u8; 32],
        password: Password,
    ) -> Result<PasswordCacheTransaction<'_>> {
        match password {
            Password::Explicit {
                password,
                cache_behavior: PasswordCacheBehavior::Remove,
            } => {
                self.remove(&id);
                Ok(PasswordCacheTransaction {
                    id,
                    password,
                    store_duration: None,
                    cache: self,
                })
            }
            Password::Explicit {
                password,
                cache_behavior: PasswordCacheBehavior::Store(duration),
            } => Ok(PasswordCacheTransaction {
                id,
                password,
                store_duration: Some(duration),
                cache: self,
            }),
            Password::FromCache => match self.get(&id)? {
                Some(password) => Ok(PasswordCacheTransaction {
                    id,
                    password,
                    store_duration: None,
                    cache: self,
                }),
                None => Err(PasswordCacheError::PasswordNotFound.into()),
            },
        }
    }

    pub fn contains(&self, id: &[u8; 32], required_duration: Duration) -> bool {
        let must_be_alive_at = now_ms() + required_duration.as_secs_f64() * 1000.0;
        match self.state.read().passwords.get(id) {
            Some(item) => item.expire_at >= must_be_alive_at,
            None => false,
        }
    }

    pub fn get(&self, id: &[u8; 32]) -> Result<Option<SecUtf8>> {
        let state = self.state.read();

        Ok(match state.passwords.get(id) {
            Some(item) => {
                let password = SecUtf8::from(String::from_utf8(
                    state
                        .cipher
                        .decrypt(&item.nonce, item.encrypted_password.as_slice())
                        .map_err(|_| PasswordCacheError::FailedToDecryptPassword)?,
                )?);
                Some(password)
            }
            None => None,
        })
    }

    pub fn store(&self, id: [u8; 32], password: &[u8], duration: Duration) -> Result<()> {
        let mut nonce = Nonce::default();
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| PasswordCacheError::FailedToGenerateNonce)?;

        let mut state = self.state.write();

        let encrypted_password = state
            .cipher
            .encrypt(&nonce, password)
            .map_err(|_| PasswordCacheError::FailedToEncryptPassword)?;

        let expire_at = now_ms() + duration.as_secs_f64() * 1000.0;

        state.passwords.insert(
            id,
            CachedPassword {
                encrypted_password,
                nonce,
                expire_at,
            },
        );

        Ok(())
    }

    pub fn remove(&self, id: &[u8; 32]) {
        self.state.write().passwords.remove(id);
    }

    pub fn clear(&self) -> Result<()> {
        let mut state = self.state.write();
        state.cipher = make_cipher()?;
        state.passwords.clear();
        Ok(())
    }

    pub fn refresh(&self) {
        let now = now_ms();
        self.state
            .write()
            .passwords
            .retain(|_, item| item.expire_at > now);
    }
}

pub struct PasswordCacheTransaction<'a> {
    id: [u8; 32],
    password: SecUtf8,
    store_duration: Option<Duration>,
    cache: &'a PasswordCache,
}

impl<'a> PasswordCacheTransaction<'a> {
    pub fn proceed(&self) {
        if let Some(duration) = self.store_duration {
            let _ = self
                .cache
                .store(self.id, self.password.unsecure().as_bytes(), duration);
        }
    }
}

impl<'a> AsRef<str> for PasswordCacheTransaction<'a> {
    fn as_ref(&self) -> &str {
        self.password.unsecure()
    }
}

struct PasswordCacheState {
    cipher: ChaCha20Poly1305,
    passwords: HashMap<[u8; 32], CachedPassword>,
}

struct CachedPassword {
    encrypted_password: Vec<u8>,
    nonce: Nonce,
    expire_at: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "data")]
pub enum Password {
    Explicit {
        password: SecUtf8,
        cache_behavior: PasswordCacheBehavior,
    },
    FromCache,
}

fn make_cipher() -> Result<ChaCha20Poly1305> {
    let mut key = chacha20poly1305::Key::default();
    ring::rand::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| PasswordCacheError::FailedToGenerateCipher)?;
    Ok(ChaCha20Poly1305::new(&key))
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum PasswordCacheBehavior {
    Store(Duration),
    Remove,
}

impl Default for PasswordCacheBehavior {
    fn default() -> Self {
        Self::Remove
    }
}

#[cfg(target_arch = "wasm32")]
fn now_ms() -> f64 {
    js_sys::Date::now()
}

#[cfg(not(target_arch = "wasm32"))]
fn now_ms() -> f64 {
    use nekoton_utils::TrustMe;
    use std::time::SystemTime;

    (SystemTime::now().duration_since(SystemTime::UNIX_EPOCH))
        .trust_me()
        .as_secs_f64()
        * 1000.0
}

#[derive(thiserror::Error, Debug)]
enum PasswordCacheError {
    #[error("Failed to generate cipher")]
    FailedToGenerateCipher,
    #[error("Failed to generate nonce")]
    FailedToGenerateNonce,
    #[error("Failed to encrypt password")]
    FailedToEncryptPassword,
    #[error("Failed to decrypt password")]
    FailedToDecryptPassword,
    #[error("Password not found")]
    PasswordNotFound,
}
