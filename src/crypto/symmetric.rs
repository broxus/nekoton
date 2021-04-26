use std::borrow::Borrow;
use std::num::NonZeroU32;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ring::{digest, pbkdf2};
use secstr::{SecUtf8, SecVec};
use thiserror::Error;

const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

#[cfg(debug_assertions)]
const N_ITER: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(1) };

///Change it to tune number of iterations in pbkdf2 function. Higher number - password bruteforce becomes slower.
/// Initial value is optimal for the current machine, so you maybe want to change it.
#[cfg(not(debug_assertions))]
const N_ITER: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(100_000) };

/// Decrypts data using specified decrypter and nonce
pub fn decrypt_secure(
    dec: &ChaCha20Poly1305,
    nonce: &Nonce,
    data: &[u8],
) -> Result<SecVec<u8>, SymmetricCryptoError> {
    decrypt(dec, nonce, data).map(SecVec::new)
}

/// Decrypts data using specified decrypter and nonce
pub fn decrypt(
    dec: &ChaCha20Poly1305,
    nonce: &Nonce,
    data: &[u8],
) -> Result<Vec<u8>, SymmetricCryptoError> {
    dec.decrypt(nonce, data)
        .map_err(|_| SymmetricCryptoError::FailedToDecryptData)
}

/// Encrypts data using specified encryptor and nonce
pub fn encrypt(
    enc: &ChaCha20Poly1305,
    nonce: &Nonce,
    data: &[u8],
) -> Result<Vec<u8>, SymmetricCryptoError> {
    enc.encrypt(nonce, data)
        .map_err(|_| SymmetricCryptoError::FailedToEncryptData)
}

// Calculates symmetric key from user password, using pbkdf2
pub fn symmetric_key_from_password(password: SecUtf8, salt: &[u8]) -> Key {
    let mut pbkdf2_hash = SecVec::new(vec![0; CREDENTIAL_LEN]);
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        N_ITER,
        salt,
        password.unsecure().as_bytes(),
        &mut pbkdf2_hash.unsecure_mut(),
    );
    Key::clone_from_slice((&pbkdf2_hash).borrow())
}

#[derive(Error, Debug)]
pub enum SymmetricCryptoError {
    #[error("Failed to decrypt data")]
    FailedToDecryptData,
    #[error("Failed to encrypt data")]
    FailedToEncryptData,
}
