//! Local JSON note store — persists note secrets between commands.
//!
//! Each record stores the private witness data for a shielded note.
//! The `cm_index` field is populated by `scan` once the note appears on-chain.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredNote {
    /// Note value in the native asset unit (planck).
    pub value: u64,
    /// Asset ID as 32-byte hex (little-endian field element).
    pub asset_id: String,
    /// Blinding factor as 32-byte hex.
    pub blinding: String,
    /// ZK owner pubkey as 32-byte hex (Poseidon(secret_key)).
    pub owner_pubkey: String,
    /// Commitment = Poseidon_t5(owner_pubkey, value, asset_id, blinding), 32-byte hex.
    pub commitment: String,
    /// Nullifier = Poseidon_t3(commitment, secret_key), 32-byte hex.
    pub nullifier: String,
    /// On-chain index. Populated by `scan`; None until observed on-chain.
    pub cm_index: Option<u64>,
    /// True once the note is spent via a transfer.
    pub spent: bool,
}

impl StoredNote {
    pub fn commitment_bytes(&self) -> Result<[u8; 32]> {
        hex32(&self.commitment)
    }
    pub fn nullifier_bytes(&self) -> Result<[u8; 32]> {
        hex32(&self.nullifier)
    }
    pub fn blinding_bytes(&self) -> Result<[u8; 32]> {
        hex32(&self.blinding)
    }
    pub fn owner_pubkey_bytes(&self) -> Result<[u8; 32]> {
        hex32(&self.owner_pubkey)
    }

    /// True if this note is known to be on-chain and not yet spent.
    pub fn is_spendable(&self) -> bool {
        self.cm_index.is_some() && !self.spent
    }
}

pub struct NoteStore {
    path: PathBuf,
    pub notes: Vec<StoredNote>,
}

impl NoteStore {
    /// Load from disk (creates empty store if file doesn't exist).
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self { path: path.to_owned(), notes: vec![] });
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read note store {}", path.display()))?;
        let notes: Vec<StoredNote> = serde_json::from_str(&raw)
            .with_context(|| format!("invalid note store JSON at {}", path.display()))?;
        Ok(Self { path: path.to_owned(), notes })
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.notes)?;
        std::fs::write(&self.path, json)
            .with_context(|| format!("cannot write note store {}", self.path.display()))
    }

    pub fn add_note(&mut self, note: StoredNote) {
        self.notes.push(note);
    }

    /// Update cm_index for a note matching by commitment hex. Returns true if found.
    pub fn mark_index(&mut self, commitment_hex: &str, index: u64) -> bool {
        for note in &mut self.notes {
            if note.commitment == commitment_hex && note.cm_index.is_none() {
                note.cm_index = Some(index);
                return true;
            }
        }
        false
    }

    /// Mark a note as spent by its nullifier hex. Returns true if found.
    pub fn mark_spent(&mut self, nullifier_hex: &str) -> bool {
        for note in &mut self.notes {
            if note.nullifier == nullifier_hex && !note.spent {
                note.spent = true;
                return true;
            }
        }
        false
    }

    /// Find the first spendable note owned by `owner_pubkey_hex`.
    pub fn find_spendable<'a>(&'a self, owner_pubkey_hex: &str) -> Option<&'a StoredNote> {
        self.notes.iter().find(|n| {
            n.owner_pubkey == owner_pubkey_hex && n.is_spendable()
        })
    }
}

/// Serialisable note secrets passed from sender to recipient out-of-band.
/// Written by `transfer --export`; consumed by `import-note`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteExport {
    /// Note value in planck.
    pub value: u64,
    /// Asset ID as 32-byte hex (little-endian Fr).
    pub asset_id: String,
    /// Blinding factor as 32-byte hex (little-endian Fr).
    pub blinding: String,
    /// Recipient ZK owner pubkey as 32-byte hex — Poseidon(recipient_sk).
    pub owner_pubkey: String,
    /// On-chain commitment as 32-byte hex — Poseidon(owner_pubkey, value, asset_id, blinding).
    /// Used by import-note to verify the secrets are self-consistent.
    pub commitment: String,
}

/// Decode a 64-char hex string (optionally with 0x prefix) into 32 bytes.
pub fn hex32(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("invalid hex")?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", s.len() / 2))
}

/// Encode 32 bytes as a lowercase hex string (no 0x prefix).
pub fn bytes32_hex(b: &[u8; 32]) -> String {
    hex::encode(b)
}
