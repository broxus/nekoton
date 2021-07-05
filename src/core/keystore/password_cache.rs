#![allow(dead_code)] // temp

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use instant::Instant;
use ring::rand::SecureRandom;
use secstr::SecUtf8;

pub struct PasswordCache {
    time: Instant,
    cipher: ChaCha20Poly1305,
    passwords: HashMap<[u8; 32], CachedPassword>,
}

impl PasswordCache {
    pub fn new() -> Result<Self> {
        Ok(Self {
            time: Instant::now(),
            cipher: make_cipher()?,
            passwords: Default::default(),
        })
    }

    pub fn contains(&self, id: &[u8; 32], required_duration: Duration) -> bool {
        let must_be_alive_at = Instant::now() + required_duration;
        match self.passwords.get(id) {
            Some(item) => item.expire_at >= must_be_alive_at,
            None => false,
        }
    }

    pub fn get(&self, id: &[u8; 32]) -> Result<Option<SecUtf8>> {
        Ok(match self.passwords.get(id) {
            Some(item) => {
                let password = SecUtf8::from(String::from_utf8(
                    self.cipher
                        .decrypt(&item.nonce, item.encrypted_password.as_slice())
                        .map_err(|_| PasswordCacheError::FailedToDecryptPassword)?,
                )?);
                Some(password)
            }
            None => None,
        })
    }

    pub fn store(&mut self, id: [u8; 32], password: &[u8], duration: Duration) -> Result<()> {
        let mut nonce = Nonce::default();
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| PasswordCacheError::FailedToGenerateNonce)?;

        self.passwords.insert(
            id,
            CachedPassword {
                encrypted_password: self
                    .cipher
                    .encrypt(&nonce, password)
                    .map_err(|_| PasswordCacheError::FailedToEncryptPassword)?,
                nonce,
                expire_at: self.time + duration,
            },
        );

        Ok(())
    }

    pub fn remove(&mut self, id: &[u8; 32]) {
        self.passwords.remove(id);
    }

    pub fn clear(&mut self) -> Result<()> {
        self.cipher = make_cipher()?;
        self.passwords.clear();
        Ok(())
    }

    pub fn refresh(&mut self) {
        let now = Instant::now();
        self.passwords.retain(|_, item| item.expire_at > now);
    }
}

struct CachedPassword {
    encrypted_password: Vec<u8>,
    nonce: Nonce,
    expire_at: Instant,
}

fn make_cipher() -> Result<ChaCha20Poly1305> {
    let mut key = chacha20poly1305::Key::default();
    ring::rand::SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| PasswordCacheError::FailedToGenerateCipher)?;
    Ok(ChaCha20Poly1305::new(&key))
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
}
