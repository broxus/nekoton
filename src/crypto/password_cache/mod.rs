use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use parking_lot::RwLock;
use rand::Rng;
use secstr::SecUtf8;
use serde::{Deserialize, Serialize};

use nekoton_utils::*;

pub struct PasswordCache {
    state: RwLock<PasswordCacheState>,
}

impl PasswordCache {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(PasswordCacheState {
                cipher: make_cipher(),
                passwords: Default::default(),
            }),
        }
    }

    pub fn reset(&self) {
        *self.state.write() = PasswordCacheState {
            cipher: make_cipher(),
            passwords: Default::default(),
        };
    }

    pub fn process_password(
        &'_ self,
        id: [u8; 32],
        password: Password,
    ) -> Result<PasswordCacheTransaction<'_>> {
        match password {
            Password::Explicit {
                password,
                cache_behavior,
            } => Ok(PasswordCacheTransaction {
                id,
                password,
                store_duration: match cache_behavior {
                    PasswordCacheBehavior::Store(duration) => Some(duration),
                    PasswordCacheBehavior::Remove => {
                        self.remove(&id);
                        None
                    }
                    PasswordCacheBehavior::Nop => None,
                },
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
        let must_be_alive_at = required_duration
            .as_secs_f64()
            .mul_add(1000.0, now_ms_f64());
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
        rand::thread_rng().fill(nonce.as_mut_slice());

        let mut state = self.state.write();

        let encrypted_password = state
            .cipher
            .encrypt(&nonce, password)
            .map_err(|_| PasswordCacheError::FailedToEncryptPassword)?;

        let expire_at = duration.as_secs_f64().mul_add(1000.0, now_ms_f64());

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

    pub fn clear(&self) {
        let mut state = self.state.write();
        state.cipher = make_cipher();
        state.passwords.clear();
    }

    pub fn refresh(&self) {
        let now = now_ms_f64();
        self.state
            .write()
            .passwords
            .retain(|_, item| item.expire_at > now);
    }
}

impl Default for PasswordCache {
    fn default() -> Self {
        Self::new()
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

fn make_cipher() -> ChaCha20Poly1305 {
    let mut key = chacha20poly1305::Key::default();
    rand::thread_rng().fill(key.as_mut_slice());
    ChaCha20Poly1305::new(&key)
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum PasswordCacheBehavior {
    /// Updates entry ttl or inserts the new entry
    Store(#[serde(with = "serde_duration_ms")] Duration),
    /// Removes the entry
    Remove,
    /// Does nothing
    Nop,
}

impl Default for PasswordCacheBehavior {
    fn default() -> Self {
        Self::Remove
    }
}

#[derive(thiserror::Error, Debug)]
enum PasswordCacheError {
    #[error("Failed to encrypt password")]
    FailedToEncryptPassword,
    #[error("Failed to decrypt password")]
    FailedToDecryptPassword,
    #[error("Password not found")]
    PasswordNotFound,
}
