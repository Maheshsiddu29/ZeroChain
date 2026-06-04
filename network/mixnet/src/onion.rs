//! Onion Encryption Layer
//!
//! Each relay peels one layer via ChaCha20-Poly1305 with HKDF key derivation

use chacha20poly1305::{
    aead::{Aead, KeyInit, Nonce},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fmt;

/// Onion encryption error
#[derive(Clone, Debug)]
pub enum OnionError {
    EncryptionFailed(String),
    DecryptionFailed(String),
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

impl std::error::Error for OnionError {}

/// Onion encryption for Mixnet
pub struct OnionEncryption {
    shared_secret: [u8; 32],
}

impl OnionEncryption {
    /// Create new onion encryptor with shared secret
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        Self {
            shared_secret: *shared_secret,
        }
    }

    /// Derive encryption key from shared secret via HKDF
    fn derive_key(&self) -> Result<[u8; 32], OnionError> {
        let hkdf = Hkdf::<Sha256>::new(None, &self.shared_secret);

        let mut key = [0u8; 32];
        hkdf.expand(b"onion-encryption-key", &mut key)
            .map_err(|_| OnionError::InvalidKeySize)?;

        Ok(key)
    }

    /// Derive nonce from shared secret
    fn derive_nonce(&self) -> Result<[u8; 12], OnionError> {
        let hkdf = Hkdf::<Sha256>::new(None, &self.shared_secret);

        let mut nonce_bytes = [0u8; 12];
        hkdf.expand(b"onion-encryption-nonce", &mut nonce_bytes)
            .map_err(|_| OnionError::InvalidNonce)?;

        Ok(nonce_bytes)
    }

    /// Encrypt data with ChaCha20-Poly1305
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let key = self.derive_key()?;
        let nonce_bytes = self.derive_nonce()?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| OnionError::EncryptionFailed(e.to_string()))?;

        let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce_bytes);

        cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| OnionError::EncryptionFailed(e.to_string()))
    }

    /// Decrypt data with ChaCha20-Poly1305
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let key = self.derive_key()?;
        let nonce_bytes = self.derive_nonce()?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| OnionError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| OnionError::DecryptionFailed(e.to_string()))
    }

    /// Encrypt data in multiple layers (for creating packets)
    pub fn encrypt_layers(
        plaintext: &[u8],
        shared_secrets: &[[u8; 32]],
    ) -> Result<Vec<u8>, OnionError> {
        let mut data = plaintext.to_vec();

        // Encrypt in reverse order (outermost layer last)
        for secret in shared_secrets.iter().rev() {
            let encryptor = Self::new(secret);
            data = encryptor.encrypt(&data)?;
        }

        Ok(data)
    }

    /// Decrypt data by peeling one layer
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

        // Peel layers in order
        let mut data = encrypted;
        for secret in &secrets {
            let decryptor = OnionEncryption::new(secret);
            data = decryptor.decrypt(&data).unwrap();
        }

        assert_eq!(data, plaintext);
    }
}