use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use pbkdf2::{pbkdf2_hmac};
use secstr::{SecUtf8, SecVec};
use zeroize::Zeroize;

pub const NONCE_LENGTH: usize = 12;

const CREDENTIAL_LEN: usize = 32;

const N_ITER: u32 = 100_000;

/// Decrypts utf8 data using specified decrypter and nonce
pub fn decrypt_secure_str(
    dec: &ChaCha20Poly1305,
    nonce: &Nonce,
    data: &[u8],
) -> Result<SecUtf8, SymmetricCryptoError> {
    String::from_utf8(decrypt(dec, nonce, data)?)
        .map(SecUtf8::from)
        .map_err(|e| {
            e.into_bytes().zeroize();
            SymmetricCryptoError::FailedToDecryptData
        })
}

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
pub fn symmetric_key_from_password(password: &str, salt: &[u8]) -> Key {
    let mut pbkdf2_hash = SecVec::new(vec![0; CREDENTIAL_LEN]);
    pbkdf2_hmac::<sha2::Sha256>(
        password.as_bytes(),
        salt,
        N_ITER,
        pbkdf2_hash.unsecure_mut(),
    );
    Key::clone_from_slice(pbkdf2_hash.unsecure())
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum SymmetricCryptoError {
    #[error("Failed to decrypt data")]
    FailedToDecryptData,
    #[error("Failed to encrypt data")]
    FailedToEncryptData,
}
