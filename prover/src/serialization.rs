//! Proof Serialization Utilities
//! 
//! Handles conversion between proof formats (binary, hex, JSON)

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::path::Path;

/// Serialize proof to binary format
pub fn serialize_proof(proof: &[u8]) -> Vec<u8> {
    proof.to_vec()
}

/// Deserialize proof from binary format
pub fn deserialize_proof(data: &[u8]) -> Result<Vec<u8>> {
    Ok(data.to_vec())
}

/// Proof metadata for JSON export
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProofMetadata {
    pub proof_type: String,
    pub proof_bytes: String,  // hex-encoded
    pub public_inputs: Vec<String>,
    pub timestamp: u64,
}

impl ProofMetadata {
    /// Create new proof metadata
    pub fn new(
        proof_type: String,
        proof_bytes: Vec<u8>,
        public_inputs: Vec<String>,
    ) -> Self {
        Self {
            proof_type,
            proof_bytes: hex::encode(proof_bytes),
            public_inputs,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Save to JSON file
    pub fn save_json(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load from JSON file
    pub fn load_json(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let metadata: ProofMetadata = serde_json::from_str(&json)?;
        Ok(metadata)
    }

    /// Get proof bytes as hex string
    pub fn get_proof_hex(&self) -> String {
        self.proof_bytes.clone()
    }

    /// Get proof bytes decoded
    pub fn get_proof_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.proof_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to decode proof hex: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_proof() {
        let proof = vec![1, 2, 3, 4, 5];
        let serialized = serialize_proof(&proof);
        assert_eq!(serialized, proof);
    }

    #[test]
    fn test_deserialize_proof() {
        let proof = vec![1, 2, 3, 4, 5];
        let deserialized = deserialize_proof(&proof).unwrap();
        assert_eq!(deserialized, proof);
    }

    #[test]
    fn test_proof_metadata_creation() {
        let metadata = ProofMetadata::new(
            "groth16".to_string(),
            vec![1, 2, 3, 4],
            vec!["0x123".to_string()],
        );

        assert_eq!(metadata.proof_type, "groth16");
        assert_eq!(metadata.proof_bytes, "01020304");
        assert_eq!(metadata.public_inputs.len(), 1);
    }

    #[test]
    fn test_proof_metadata_roundtrip() {
        let metadata = ProofMetadata::new(
            "zk-origin".to_string(),
            vec![10, 20, 30],
            vec!["genesis".to_string(), "final".to_string()],
        );

        let bytes = metadata.get_proof_bytes().unwrap();
        assert_eq!(bytes, vec![10, 20, 30]);
    }
}