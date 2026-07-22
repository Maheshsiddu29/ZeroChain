//! BLS Consensus Types and Data Structures

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

/// BLS Public Key (48 bytes for BLS12-381)
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq, Hash, MaxEncodedLen)]
pub struct BlsPublicKey(pub [u8; 48]);

impl BlsPublicKey {
    pub fn new(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Default for BlsPublicKey {
    fn default() -> Self {
        Self([0u8; 48])
    }
}

/// BLS Signature (96 bytes for BLS12-381)
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq, MaxEncodedLen)]
pub struct BlsSignature(pub [u8; 96]);

impl BlsSignature {
    pub fn new(bytes: [u8; 96]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 96] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Default for BlsSignature {
    fn default() -> Self {
        Self([0u8; 96])
    }
}

/// BLS Private Key (32 bytes)
#[derive(Clone, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct BlsPrivateKey(pub [u8; 32]);

impl BlsPrivateKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for BlsPrivateKey {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

/// Threshold configuration for BLS signature aggregation
#[derive(Clone, Copy, Debug, Encode, Decode, TypeInfo, PartialEq, Eq, Default, MaxEncodedLen)]
pub struct ThresholdConfig {
    /// Total number of signers (n)
    pub total: u16,
    /// Required threshold (t)
    pub threshold: u16,
}

impl ThresholdConfig {
    pub fn new(total: u16, threshold: u16) -> Result<Self, &'static str> {
        if threshold > total {
            return Err("Threshold cannot exceed total");
        }
        if threshold == 0 {
            return Err("Threshold must be positive");
        }
        Ok(Self { total, threshold })
    }

    pub fn is_valid(&self) -> bool {
        self.threshold > 0 && self.threshold <= self.total
    }
}

/// Partial BLS signature from a single signer
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq, MaxEncodedLen)]
pub struct PartialSignature {
    /// Signer index (0 to n-1)
    pub signer_id: u16,
    /// Partial signature (96 bytes)
    pub signature: BlsSignature,
    /// Block hash being signed
    pub block_hash: [u8; 32],
}

impl PartialSignature {
    pub fn new(signer_id: u16, signature: BlsSignature, block_hash: [u8; 32]) -> Self {
        Self {
            signer_id,
            signature,
            block_hash,
        }
    }
}

impl Default for PartialSignature {
    fn default() -> Self {
        Self {
            signer_id: 0,
            signature: BlsSignature::default(),
            block_hash: [0u8; 32],
        }
    }
}

/// Aggregate BLS signature with metadata
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq, MaxEncodedLen)]
pub struct AggregateSignature {
    /// Aggregated signature (96 bytes)
    pub signature: BlsSignature,
    /// Block hash signed
    pub block_hash: [u8; 32],
    /// Bitmap of participating signers (max 256 signers = 32 bytes)
    pub signer_bitmap: [u8; 32],
    /// Number of signatures aggregated
    pub signature_count: u16,
}

impl AggregateSignature {
    pub fn new(
        signature: BlsSignature,
        block_hash: [u8; 32],
        signer_bitmap: Vec<u8>,
        signature_count: u16,
    ) -> Self {
        let mut bitmap = [0u8; 32];
        for (i, &byte) in signer_bitmap.iter().enumerate().take(32) {
            bitmap[i] = byte;
        }

        Self {
            signature,
            block_hash,
            signer_bitmap: bitmap,
            signature_count,
        }
    }

    pub fn is_valid_for_threshold(&self, threshold: u16) -> bool {
        self.signature_count >= threshold
    }
}

impl Default for AggregateSignature {
    fn default() -> Self {
        Self {
            signature: BlsSignature::default(),
            block_hash: [0u8; 32],
            signer_bitmap: [0u8; 32],
            signature_count: 0,
        }
    }
}

/// DKG (Distributed Key Generation) Share
#[derive(Clone, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct DkgShare {
    /// Participant index
    pub participant_id: u16,
    /// Secret share (32 bytes)
    pub share: [u8; 32],
    /// Commitments to polynomial coefficients (max 48 commitments)
    pub commitments: [Option<[u8; 48]>; 48],
}

impl DkgShare {
    pub fn new(
        participant_id: u16,
        share: [u8; 32],
        commitments: Vec<[u8; 48]>,
    ) -> Self {
        let mut comms = [None; 48];
        for (i, comm) in commitments.iter().enumerate().take(48) {
            comms[i] = Some(*comm);
        }

        Self {
            participant_id,
            share,
            commitments: comms,
        }
    }
}

impl Default for DkgShare {
    fn default() -> Self {
        Self {
            participant_id: 0,
            share: [0u8; 32],
            commitments: [None; 48],
        }
    }
}

/// DKG Complaint (for disqualifying bad participants)
#[derive(Clone, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct DkgComplaint {
    /// Complainant index
    pub complainer_id: u16,
    /// Accused participant index
    pub accused_id: u16,
    /// Evidence (max 256 bytes)
    pub evidence: [u8; 256],
}

impl Default for DkgComplaint {
    fn default() -> Self {
        Self {
            complainer_id: 0,
            accused_id: 0,
            evidence: [0u8; 256],
        }
    }
}

/// Finalized block record
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq, MaxEncodedLen)]
pub struct FinalizedBlock {
    /// Block hash
    pub block_hash: [u8; 32],
    /// Block number
    pub block_number: u32,
    /// Aggregate signature
    pub aggregate_signature: AggregateSignature,
    /// Epoch number
    pub epoch: u64,
}

impl FinalizedBlock {
    pub fn new(
        block_hash: [u8; 32],
        block_number: u32,
        aggregate_signature: AggregateSignature,
        epoch: u64,
    ) -> Self {
        Self {
            block_hash,
            block_number,
            aggregate_signature,
            epoch,
        }
    }
}

impl Default for FinalizedBlock {
    fn default() -> Self {
        Self {
            block_hash: [0u8; 32],
            block_number: 0,
            aggregate_signature: AggregateSignature::default(),
            epoch: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_config_validation() {
        assert!(ThresholdConfig::new(3, 2).is_ok());
        assert!(ThresholdConfig::new(3, 3).is_ok());
        assert!(ThresholdConfig::new(3, 4).is_err());
        assert!(ThresholdConfig::new(3, 0).is_err());
    }

    #[test]
    fn test_bls_key_encoding() {
        let pk = BlsPublicKey::new([1u8; 48]);
        let encoded = pk.encode();
        let decoded = BlsPublicKey::decode(&mut &encoded[..]).unwrap();
        assert_eq!(pk, decoded);
    }

    #[test]
    fn test_aggregate_signature_threshold_check() {
        let agg = AggregateSignature::new(
            BlsSignature::new([0u8; 96]),
            [1u8; 32],
            vec![0b11u8],
            2,
        );

        assert!(agg.is_valid_for_threshold(2));
        assert!(!agg.is_valid_for_threshold(3));
    }

    #[test]
    fn test_defaults() {
        let pk = BlsPublicKey::default();
        assert_eq!(pk.0, [0u8; 48]);

        let sig = BlsSignature::default();
        assert_eq!(sig.0, [0u8; 96]);

        let config = ThresholdConfig::default();
        assert_eq!(config.total, 0);
        assert_eq!(config.threshold, 0);
    }
}