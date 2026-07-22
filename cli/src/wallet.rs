//! Wallet key management — H-09: keyfile encrypted at rest.
//!
//! File format (version 1):
//!   {
//!     "version": 1,
//!     "argon2": { "m_cost": 65536, "t_cost": 3, "p_cost": 1 },
//!     "salt":        "<32-byte hex>",
//!     "nonce":       "<12-byte hex>",
//!     "ciphertext":  "<hex>"
//!   }
//!
//! KDF: Argon2id (m=64 MiB, t=3, p=1) → 32-byte AES key.
//! Cipher: AES-256-GCM.  The plaintext is the JSON `{"secret_key":"…","public_key":"…"}`.

use anyhow::{bail, Context, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

type Hash256 = [u8; 32];

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    pub secret: Hash256,
    pub public: Hash256,
}

impl Keypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let public = zc_crypto::poseidon::PoseidonHasher::hash_one(&secret);
        Self { secret, public }
    }

    /// Load and decrypt a keypair from an encrypted keyfile.
    ///
    /// Prompts for the password on the terminal (no echo).
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let password = rpassword::prompt_password("Keyfile password: ")
            .context("failed to read password")?;
        Self::from_file_with_password(path, &password)
    }

    /// Load and decrypt a keypair using an explicit password (for tests / non-interactive).
    pub fn from_file_with_password(path: &std::path::Path, password: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read keyfile {}", path.display()))?;
        let outer: serde_json::Value = serde_json::from_str(&raw)?;

        match outer["version"].as_u64() {
            Some(1) => decrypt_v1(outer, password),
            other => bail!("unsupported keyfile version: {:?}", other),
        }
    }

    /// Encrypt and save the keypair to a keyfile.
    ///
    /// Prompts for a new password (twice, for confirmation) on the terminal.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let password = rpassword::prompt_password("New keyfile password: ")
            .context("failed to read password")?;
        let confirm = rpassword::prompt_password("Confirm password: ")
            .context("failed to read password confirmation")?;
        if password != confirm {
            bail!("passwords do not match");
        }
        self.save_to_file_with_password(path, &password)
    }

    /// Encrypt and save using an explicit password (for tests / non-interactive).
    pub fn save_to_file_with_password(&self, path: &std::path::Path, password: &str) -> Result<()> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use aes_gcm::aead::Aead;
        use argon2::{Argon2, Algorithm, Version, Params};
        use rand::RngCore;

        const M_COST: u32 = 65_536; // 64 MiB
        const T_COST: u32 = 3;
        const P_COST: u32 = 1;

        let mut rng = rand::thread_rng();

        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);

        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);

        // Derive AES key with Argon2id
        let params = Params::new(M_COST, T_COST, P_COST, Some(32))
            .map_err(|e| anyhow::anyhow!("Argon2 params: {:?}", e))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key_bytes = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Argon2 KDF: {:?}", e))?;

        // Plaintext: JSON with secret + public keys
        let plaintext = serde_json::json!({
            "secret_key": format!("0x{}", hex::encode(self.secret)),
            "public_key": format!("0x{}", hex::encode(self.public)),
        })
        .to_string();
        let plaintext_bytes = plaintext.as_bytes();

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| anyhow::anyhow!("AES-256-GCM init: {:?}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext_bytes)
            .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {:?}", e))?;

        key_bytes.zeroize();

        let envelope = serde_json::json!({
            "version": 1,
            "argon2": { "m_cost": M_COST, "t_cost": T_COST, "p_cost": P_COST },
            "salt":       hex::encode(salt),
            "nonce":      hex::encode(nonce_bytes),
            "ciphertext": hex::encode(ciphertext),
        });

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&envelope)?)
            .with_context(|| format!("cannot write keyfile {}", path.display()))?;

        Ok(())
    }
}

fn decrypt_v1(outer: serde_json::Value, password: &str) -> Result<Keypair> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    use argon2::{Argon2, Algorithm, Version, Params};

    let m_cost = outer["argon2"]["m_cost"].as_u64().unwrap_or(65_536) as u32;
    let t_cost = outer["argon2"]["t_cost"].as_u64().unwrap_or(3) as u32;
    let p_cost = outer["argon2"]["p_cost"].as_u64().unwrap_or(1) as u32;

    let salt = hex_field(&outer, "salt")?;
    let nonce_bytes = hex_field(&outer, "nonce")?;
    let ciphertext = hex_field(&outer, "ciphertext")?;

    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2 params: {:?}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key_bytes)
        .map_err(|e| anyhow::anyhow!("Argon2 KDF: {:?}", e))?;

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM init: {:?}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes[..12]);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong password or corrupt keyfile"))?;

    key_bytes.zeroize();

    let inner: serde_json::Value = serde_json::from_slice(&plaintext)?;
    let secret = hex_to_hash256(
        inner["secret_key"].as_str().ok_or_else(|| anyhow::anyhow!("missing secret_key"))?,
    )?;
    let public = hex_to_hash256(
        inner["public_key"].as_str().ok_or_else(|| anyhow::anyhow!("missing public_key"))?,
    )?;

    Ok(Keypair { secret, public })
}

fn hex_field(v: &serde_json::Value, field: &str) -> Result<Vec<u8>> {
    let s = v[field]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("keyfile missing field '{}'", field))?;
    hex::decode(s).with_context(|| format!("field '{}' is not valid hex", field))
}

fn hex_to_hash256(hex: &str) -> Result<Hash256> {
    let hex_clean = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex_clean)?;
    if bytes.len() != 32 {
        bail!("expected 32-byte hash, got {} bytes", bytes.len());
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let kp = Keypair::generate();
        let file = NamedTempFile::new().unwrap();
        kp.save_to_file_with_password(file.path(), "testpass").unwrap();
        let kp2 = Keypair::from_file_with_password(file.path(), "testpass").unwrap();
        assert_eq!(kp.secret, kp2.secret);
        assert_eq!(kp.public, kp2.public);
    }

    #[test]
    fn wrong_password_fails() {
        let kp = Keypair::generate();
        let file = NamedTempFile::new().unwrap();
        kp.save_to_file_with_password(file.path(), "correct").unwrap();
        assert!(Keypair::from_file_with_password(file.path(), "wrong").is_err());
    }
}
