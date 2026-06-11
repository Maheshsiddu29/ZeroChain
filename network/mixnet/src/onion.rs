//! Onion Encryption Layer

use alloc::vec::Vec;
use core::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Nonce},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::Sha256;

/// Onion encryption error
#[derive(Clone, Debug)]
pub enum OnionError {
    EncryptionFailed(alloc::string::String),
    DecryptionFailed(alloc::string::String),
    InvalidKeySize,
    InvalidNonce,
}

impl fmt::Display for OnionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            Self::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            Self::InvalidKeySize => write!(f, "Invalid key size"),
            Self::InvalidNonce => write!(f, "Invalid nonce"),
        }
    }
}

/// Onion encryption for Mixnet
pub struct OnionEncryption {
    shared_secret: [u8; 32],
}

impl OnionEncryption {
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        Self {
            shared_secret: *shared_secret,
        }
    }

    fn derive_key(&self) -> Result<[u8; 32], OnionError> {
        let hkdf = Hkdf::<Sha256>::new(None, &self.shared_secret);
        let mut key = [0u8; 32];
        hkdf.expand(b"onion-encryption-key", &mut key)
            .map_err(|_| OnionError::InvalidKeySize)?;
        Ok(key)
    }

    fn derive_nonce(&self) -> Result<[u8; 12], OnionError> {
        let hkdf = Hkdf::<Sha256>::new(None, &self.shared_secret);
        let mut nonce_bytes = [0u8; 12];
        hkdf.expand(b"onion-encryption-nonce", &mut nonce_bytes)
            .map_err(|_| OnionError::InvalidNonce)?;
        Ok(nonce_bytes)
    }

 pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
    let key = self.derive_key()?;
    let nonce_bytes = self.derive_nonce()?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| OnionError::EncryptionFailed(alloc::format!("{:?}", e)))?;

    let nonce: chacha20poly1305::Nonce = *chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| OnionError::EncryptionFailed(alloc::format!("{:?}", e)))
}

pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
    let key = self.derive_key()?;
    let nonce_bytes = self.derive_nonce()?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| OnionError::DecryptionFailed(alloc::format!("{:?}", e)))?;

    let nonce: chacha20poly1305::Nonce = *chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| OnionError::DecryptionFailed(alloc::format!("{:?}", e)))
}
    

    pub fn encrypt_layers(
        plaintext: &[u8],
        shared_secrets: &[[u8; 32]],
    ) -> Result<Vec<u8>, OnionError> {
        let mut data = plaintext.to_vec();

        for secret in shared_secrets.iter().rev() {
            let encryptor = Self::new(secret);
            data = encryptor.encrypt(&data)?;
        }

        Ok(data)
    }

    pub fn decrypt_and_peel(&self, ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
        self.decrypt(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Secret message for relay";
        let shared_secret = [42u8; 32];

        let encryption = OnionEncryption::new(&shared_secret);

        let ciphertext = encryption.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = encryption.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_secrets_produce_different_ciphertexts() {
        let plaintext = b"Same message";
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];

        let enc1 = OnionEncryption::new(&secret1);
        let enc2 = OnionEncryption::new(&secret2);

        let cipher1 = enc1.encrypt(plaintext).unwrap();
        let cipher2 = enc2.encrypt(plaintext).unwrap();

        assert_ne!(cipher1, cipher2);
    }

    #[test]
    fn test_multilayer_encryption() {
        let plaintext = b"Original message";
        let secrets = [[1u8; 32], [2u8; 32], [3u8; 32]];

        let encrypted = OnionEncryption::encrypt_layers(plaintext, &secrets).unwrap();

        let mut data = encrypted;
        for secret in &secrets {
            let decryptor = OnionEncryption::new(secret);
            data = decryptor.decrypt(&data).unwrap();
        }

        assert_eq!(data, plaintext);
    }
}