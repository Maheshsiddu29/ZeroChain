//! Wallet key management

use zc_crypto::Hash256;
use zeroize::Zeroize;
use anyhow::Result;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Keypair {
    pub secret: Hash256,
    pub public: Hash256,
}

impl Keypair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut rng = rand::thread_rng();

        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);

        // Derive public key from secret
        let public = zc_crypto::PoseidonHasher::hash_one(&secret);

        Self { secret, public }
    }

    /// Load keypair from file
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(path)?
        )?;

        let secret_hex = json["secret_key"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing secret_key"))?;
        let public_hex = json["public_key"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing public_key"))?;

        let secret = hex_to_hash256(secret_hex)?;
        let public = hex_to_hash256(public_hex)?;

        Ok(Self { secret, public })
    }
}

fn hex_to_hash256(hex: &str) -> Result<Hash256> {
    let hex_clean = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex_clean)?;

    if bytes.len() != 32 {
        return Err(anyhow::anyhow!("Hash must be 32 bytes"));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}