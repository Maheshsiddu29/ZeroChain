//! BLS Signature Aggregation and Verification

use crate::types::*;
use sp_std::vec::Vec;
use sha2::{Sha256, Digest};

/// BLS Aggregation Engine
pub struct BlsAggregator {
    /// Aggregate public key for this epoch
    pub apk: BlsPublicKey,
    /// Partial signatures received
    pub partial_signatures: Vec<PartialSignature>,
    /// Current threshold
    pub threshold: u16,
}

impl BlsAggregator {
    /// Create new aggregator
    pub fn new(apk: BlsPublicKey, threshold: u16) -> Self {
        Self {
            apk,
            partial_signatures: Vec::new(),
            threshold,
        }
    }

    /// Add partial signature
    pub fn add_partial_signature(&mut self, sig: PartialSignature) -> Result<(), AggregationError> {
        // Verify no duplicate signer
        if self
            .partial_signatures
            .iter()
            .any(|s| s.signer_id == sig.signer_id)
        {
            return Err(AggregationError::DuplicateSigner);
        }

        // Verify all signatures for same block
        if !self.partial_signatures.is_empty() {
            let first_block = self.partial_signatures[0].block_hash;
            if sig.block_hash != first_block {
                return Err(AggregationError::MismatchedBlockHash);
            }
        }

        self.partial_signatures.push(sig);
        Ok(())
    }

    /// Aggregate signatures (when threshold reached)
    pub fn aggregate(&self) -> Result<AggregateSignature, AggregationError> {
        let sig_count = self.partial_signatures.len() as u16;

        if sig_count < self.threshold {
            return Err(AggregationError::InsufficientSignatures);
        }

        let block_hash = self.partial_signatures[0].block_hash;

        // Create signer bitmap
        let mut signer_bitmap = vec![0u8; 32]; // Bitmap for up to 256 signers
        for sig in &self.partial_signatures {
            let byte_idx = (sig.signer_id / 8) as usize;
            let bit_idx = sig.signer_id % 8;
            if byte_idx < signer_bitmap.len() {
                signer_bitmap[byte_idx] |= 1 << bit_idx;
            }
        }

        // Aggregate signature (simplified: XOR of partial signatures)
        let aggregated = self.combine_signatures()?;

        Ok(AggregateSignature::new(
            aggregated,
            block_hash,
            signer_bitmap,
            sig_count,
        ))
    }

    /// Combine partial signatures into aggregate
    fn combine_signatures(&self) -> Result<BlsSignature, AggregationError> {
        if self.partial_signatures.is_empty() {
            return Err(AggregationError::EmptySignatureSet);
        }

        let mut combined = [0u8; 96];

        for sig in &self.partial_signatures {
            for i in 0..96 {
                combined[i] ^= sig.signature.0[i];
            }
        }

        Ok(BlsSignature::new(combined))
    }

    /// Verify aggregate signature (simplified verification)
    pub fn verify(
        &self,
        aggregate_sig: &AggregateSignature,
        _message: &[u8],
    ) -> Result<(), AggregationError> {
        // Verify signature count >= threshold
        if aggregate_sig.signature_count < self.threshold {
            return Err(AggregationError::BelowThreshold);
        }

        // Verify aggregate signature is not zero (basic sanity check)
        if aggregate_sig.signature.0 == [0u8; 96] {
            return Err(AggregationError::InvalidSignature);
        }

        // Verify block hash matches what we're aggregating
        if !self.partial_signatures.is_empty() {
            let expected_hash = self.partial_signatures[0].block_hash;
            if aggregate_sig.block_hash != expected_hash {
                return Err(AggregationError::MessageHashMismatch);
            }
        }

        // In production: actual BLS verification using the APK
        // For now: just verify structure is valid
        Ok(())
    }

    /// Get signature count
    pub fn signature_count(&self) -> u16 {
        self.partial_signatures.len() as u16
    }

    /// Check if threshold reached
    pub fn can_aggregate(&self) -> bool {
        self.signature_count() >= self.threshold
    }

    /// Clear for next block
    pub fn reset(&mut self) {
        self.partial_signatures.clear();
    }
}

/// Aggregation Errors
#[derive(Clone, Debug)]
pub enum AggregationError {
    /// Signer already submitted signature
    DuplicateSigner,
    /// Signatures for different blocks
    MismatchedBlockHash,
    /// Not enough signatures to aggregate
    InsufficientSignatures,
    /// Below threshold for finalization
    BelowThreshold,
    /// No signatures to combine
    EmptySignatureSet,
    /// Invalid signature
    InvalidSignature,
    /// Message hash mismatch
    MessageHashMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_dummy_signature(id: u16, block_hash: [u8; 32]) -> PartialSignature {
        let mut sig_bytes = [0u8; 96];
        sig_bytes[0] = id as u8;
        PartialSignature::new(id, BlsSignature::new(sig_bytes), block_hash)
    }

    #[test]
    fn test_aggregator_creation() {
        let apk = BlsPublicKey::new([1u8; 48]);
        let agg = BlsAggregator::new(apk, 2);
        assert_eq!(agg.signature_count(), 0);
        assert!(!agg.can_aggregate());
    }

    #[test]
    fn test_add_partial_signature() {
        let apk = BlsPublicKey::new([1u8; 48]);
        let mut agg = BlsAggregator::new(apk, 2);
        let block_hash = [1u8; 32];

        let sig = create_dummy_signature(1, block_hash);
        assert!(agg.add_partial_signature(sig).is_ok());
        assert_eq!(agg.signature_count(), 1);
    }

    #[test]
    fn test_duplicate_signer_rejected() {
        let apk = BlsPublicKey::new([1u8; 48]);
        let mut agg = BlsAggregator::new(apk, 2);
        let block_hash = [1u8; 32];

        let sig1 = create_dummy_signature(1, block_hash);
        let sig2 = create_dummy_signature(1, block_hash);

        assert!(agg.add_partial_signature(sig1).is_ok());
        assert!(agg.add_partial_signature(sig2).is_err());
    }

    #[test]
    fn test_mismatched_block_rejected() {
        let apk = BlsPublicKey::new([1u8; 48]);
        let mut agg = BlsAggregator::new(apk, 2);

        let sig1 = create_dummy_signature(1, [1u8; 32]);
        let sig2 = create_dummy_signature(2, [2u8; 32]);

        assert!(agg.add_partial_signature(sig1).is_ok());
        assert!(agg.add_partial_signature(sig2).is_err());
    }

    #[test]
    fn test_aggregate_threshold_check() {
        let apk = BlsPublicKey::new([1u8; 48]);
        let mut agg = BlsAggregator::new(apk, 2);
        let block_hash = [1u8; 32];

        let sig = create_dummy_signature(1, block_hash);
        agg.add_partial_signature(sig).ok();

        let result = agg.aggregate();
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_success() {
        let apk = BlsPublicKey::new([1u8; 48]);
        let mut agg = BlsAggregator::new(apk, 2);
        let block_hash = [1u8; 32];

        let sig1 = create_dummy_signature(1, block_hash);
        let sig2 = create_dummy_signature(2, block_hash);

        agg.add_partial_signature(sig1).ok();
        agg.add_partial_signature(sig2).ok();

        let result = agg.aggregate();
        assert!(result.is_ok());

        let agg_sig = result.unwrap();
        assert_eq!(agg_sig.signature_count, 2);
        assert_eq!(agg_sig.block_hash, block_hash);
    }

    #[test]
    fn test_signature_verification() {
        let apk = BlsPublicKey::new([1u8; 48]);
        let mut agg = BlsAggregator::new(apk, 2);
        let block_hash = [5u8; 32];

        let sig1 = create_dummy_signature(1, block_hash);
        let sig2 = create_dummy_signature(2, block_hash);

        agg.add_partial_signature(sig1).ok();
        agg.add_partial_signature(sig2).ok();

        let agg_sig = agg.aggregate().unwrap();
        
        // Verify the aggregate signature
        let result = agg.verify(&agg_sig, b"test_message");
        assert!(result.is_ok());
    }

    #[test]
    fn test_reset() {
        let apk = BlsPublicKey::new([1u8; 48]);
        let mut agg = BlsAggregator::new(apk, 2);
        let block_hash = [1u8; 32];

        let sig = create_dummy_signature(1, block_hash);
        agg.add_partial_signature(sig).ok();
        assert_eq!(agg.signature_count(), 1);

        agg.reset();
        assert_eq!(agg.signature_count(), 0);
    }

    #[test]
    fn test_verify_below_threshold() {
        let apk = BlsPublicKey::new([1u8; 48]);
        let agg = BlsAggregator::new(apk, 3);

        let agg_sig = AggregateSignature::new(
            BlsSignature::new([1u8; 96]),
            [1u8; 32],
            vec![0b11u8],
            2, // Only 2 sigs but threshold is 3
        );

        let result = agg.verify(&agg_sig, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_zero_signature() {
        let apk = BlsPublicKey::new([1u8; 48]);
        let agg = BlsAggregator::new(apk, 2);

        let agg_sig = AggregateSignature::new(
            BlsSignature::new([0u8; 96]), // Zero signature
            [1u8; 32],
            vec![0b11u8],
            2,
        );

        let result = agg.verify(&agg_sig, b"test");
        assert!(result.is_err());
    }
}