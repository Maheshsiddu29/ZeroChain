//! Note-memo encryption for recipient discovery (Sapling-style).
//!
//! ENCRYPTION: X25519 ECDH → HKDF-SHA256 → ChaCha20Poly1305.
//!
//! Memo format (140 bytes):
//!   [0..32]   ephemeral X25519 public key
//!   [32..44]  ChaCha20Poly1305 nonce (12 bytes)
//!   [44..140] ciphertext = Encrypt(80-byte plaintext) → 96 bytes (80 payload + 16 AEAD tag)
//!
//! Plaintext (80 bytes):
//!   [0..8]   value as little-endian u64
//!   [8..40]  blinding (32 bytes, little-endian Fr)
//!   [40..72] asset_id (32 bytes, little-endian Fr)
//!   [72..80] padding (zeros)
//!
//! IVK derivation:
//!   HKDF-SHA256(ikm=wallet.secret, salt=None, info=b"ZeroChain-IVK-v1") → 32 bytes
//!
//! Key agreement per note:
//!   shared   = ECDH(ephemeral_secret, recipient_ivk_pub)
//!   note_key = HKDF-SHA256(ikm=shared, salt=None, info=b"ZeroChain-note-key-v1") → 32 bytes

use anyhow::Result;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce as ChaNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub const MEMO_LEN: usize = 140;
const PLAINTEXT_LEN: usize = 80;

#[derive(Debug, Clone)]
pub struct NotePlaintext {
    pub value: u64,
    pub blinding: [u8; 32],
    pub asset_id: [u8; 32],
}

impl NotePlaintext {
    fn to_bytes(&self) -> [u8; PLAINTEXT_LEN] {
        let mut buf = [0u8; PLAINTEXT_LEN];
        buf[0..8].copy_from_slice(&self.value.to_le_bytes());
        buf[8..40].copy_from_slice(&self.blinding);
        buf[40..72].copy_from_slice(&self.asset_id);
        // [72..80] = zeros (padding)
        buf
    }

    fn from_bytes(buf: &[u8; PLAINTEXT_LEN]) -> Self {
        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&buf[0..8]);
        let mut blinding = [0u8; 32];
        blinding.copy_from_slice(&buf[8..40]);
        let mut asset_id = [0u8; 32];
        asset_id.copy_from_slice(&buf[40..72]);
        NotePlaintext { value: u64::from_le_bytes(value_bytes), blinding, asset_id }
    }
}

pub struct IncomingViewingKey {
    private: StaticSecret,
    pub public: [u8; 32],
}

impl IncomingViewingKey {
    /// Derive an IVK from the wallet spend key.
    /// Separation from the spend key ensures that a recipient can delegate
    /// note-scanning without granting spend authority.
    pub fn from_spend_key(sk: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, sk);
        let mut raw = [0u8; 32];
        hk.expand(b"ZeroChain-IVK-v1", &mut raw)
            .expect("32-byte HKDF output is always valid");
        let private = StaticSecret::from(raw);
        let public = X25519PublicKey::from(&private).to_bytes();
        raw.fill(0); // zeroize intermediate key material
        Self { private, public }
    }

    /// Trial-decrypt a 140-byte memo.  Returns `None` on authentication failure or
    /// any length mismatch — both are silent to prevent oracle attacks.
    pub fn try_decrypt(&self, memo: &[u8]) -> Option<NotePlaintext> {
        if memo.len() != MEMO_LEN {
            return None;
        }
        let mut eph_pk_bytes = [0u8; 32];
        eph_pk_bytes.copy_from_slice(&memo[0..32]);
        let eph_pk = X25519PublicKey::from(eph_pk_bytes);

        let shared = self.private.diffie_hellman(&eph_pk);
        let note_key = derive_note_key(shared.as_bytes());

        let nonce = ChaNonce::from_slice(&memo[32..44]);
        let cipher = ChaCha20Poly1305::new_from_slice(&note_key).ok()?;
        let plaintext = cipher.decrypt(nonce, &memo[44..]).ok()?;

        if plaintext.len() != PLAINTEXT_LEN {
            return None;
        }
        let mut buf = [0u8; PLAINTEXT_LEN];
        buf.copy_from_slice(&plaintext);
        Some(NotePlaintext::from_bytes(&buf))
    }
}

/// Encrypt a note plaintext for a recipient identified by their IVK public key.
/// Uses a fresh ephemeral X25519 key (from `rng`) so each encryption is unique.
pub fn encrypt_note_memo(
    recipient_ivk_pk: &[u8; 32],
    pt: &NotePlaintext,
    rng: &mut impl rand::RngCore,
) -> Result<Vec<u8>> {
    // Ephemeral keypair — treat random bytes as X25519 private key (clamped by StaticSecret::from)
    let mut eph_seed = [0u8; 32];
    rng.fill_bytes(&mut eph_seed);
    let eph_secret = StaticSecret::from(eph_seed);
    eph_seed.fill(0); // zeroize immediately after use
    let eph_public = X25519PublicKey::from(&eph_secret);

    let recipient_pk = X25519PublicKey::from(*recipient_ivk_pk);
    let shared = eph_secret.diffie_hellman(&recipient_pk);
    let note_key = derive_note_key(shared.as_bytes());

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = ChaNonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&note_key)
        .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 init: {:?}", e))?;
    let ciphertext = cipher
        .encrypt(nonce, pt.to_bytes().as_slice())
        .map_err(|e| anyhow::anyhow!("encrypt: {:?}", e))?;

    // memo = eph_pk(32) || nonce(12) || ciphertext(96)
    let mut memo = Vec::with_capacity(MEMO_LEN);
    memo.extend_from_slice(eph_public.as_bytes());
    memo.extend_from_slice(&nonce_bytes);
    memo.extend_from_slice(&ciphertext);
    debug_assert_eq!(memo.len(), MEMO_LEN, "memo must be exactly 140 bytes");

    Ok(memo)
}

fn derive_note_key(shared_bytes: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_bytes);
    let mut key = [0u8; 32];
    hk.expand(b"ZeroChain-note-key-v1", &mut key)
        .expect("32-byte HKDF output is always valid");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let sk = [42u8; 32];
        let ivk = IncomingViewingKey::from_spend_key(&sk);

        let pt = NotePlaintext {
            value: 1_000_000,
            blinding: [0xABu8; 32],
            asset_id: [0u8; 32],
        };

        let mut rng = rand::thread_rng();
        let memo = encrypt_note_memo(&ivk.public, &pt, &mut rng).unwrap();
        assert_eq!(memo.len(), MEMO_LEN);

        let decrypted = ivk.try_decrypt(&memo).expect("decryption must succeed");
        assert_eq!(decrypted.value, pt.value);
        assert_eq!(decrypted.blinding, pt.blinding);
        assert_eq!(decrypted.asset_id, pt.asset_id);
    }

    #[test]
    fn wrong_key_returns_none() {
        let sender_sk = [1u8; 32];
        let receiver_sk = [2u8; 32];
        let attacker_sk = [3u8; 32];

        let receiver_ivk = IncomingViewingKey::from_spend_key(&receiver_sk);
        let attacker_ivk = IncomingViewingKey::from_spend_key(&attacker_sk);
        let _ = IncomingViewingKey::from_spend_key(&sender_sk);

        let pt = NotePlaintext { value: 1, blinding: [0u8; 32], asset_id: [0u8; 32] };
        let mut rng = rand::thread_rng();
        let memo = encrypt_note_memo(&receiver_ivk.public, &pt, &mut rng).unwrap();

        assert!(attacker_ivk.try_decrypt(&memo).is_none());
        assert!(receiver_ivk.try_decrypt(&memo).is_some());
    }

    #[test]
    fn tampered_memo_returns_none() {
        let sk = [9u8; 32];
        let ivk = IncomingViewingKey::from_spend_key(&sk);
        let pt = NotePlaintext { value: 500, blinding: [0u8; 32], asset_id: [0u8; 32] };
        let mut rng = rand::thread_rng();
        let mut memo = encrypt_note_memo(&ivk.public, &pt, &mut rng).unwrap();
        memo[50] ^= 0xFF; // flip a byte in the ciphertext
        assert!(ivk.try_decrypt(&memo).is_none());
    }

    #[test]
    fn different_spend_keys_give_different_ivk_pubkeys() {
        let ivk_a = IncomingViewingKey::from_spend_key(&[1u8; 32]);
        let ivk_b = IncomingViewingKey::from_spend_key(&[2u8; 32]);
        assert_ne!(ivk_a.public, ivk_b.public);
    }
}
