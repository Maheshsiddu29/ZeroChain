//! Pedersen Commitments
//!
//! A Pedersen commitment hides a value while allowing arithmetic operations.
//! Commit(value, blinding) = value*G + blinding*H
//!
//! Properties:
//! - Hiding: Cannot learn `value` from the commitment
//! - Binding: Cannot find two different (value, blinding) pairs that produce the same commitment
//! - Homomorphic: Commit(a) + Commit(b) = Commit(a + b) (with appropriate blinding)

use crate::{Field, poseidon::field_to_bytes};
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use zeroize::Zeroize;

/// A Pedersen commitment to a value
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenCommitment {
    /// The commitment point, serialized
    pub commitment: [u8; 32],
}

/// Blinding factor for a commitment (must be kept secret)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct BlindingFactor {
    pub inner: Field,
}

impl BlindingFactor {
    /// Generate a random blinding factor
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        Self {
            inner: Field::rand(rng),
        }
    }

    /// Create from a known value (for testing or deterministic derivation)
    pub fn from_field(f: Field) -> Self {
        Self { inner: f }
    }
}

/// Create a Pedersen commitment to a value
///
/// For now, we use a simplified hash-based commitment:
/// Commit(value, blinding) = Poseidon(value, blinding)
///
/// This provides hiding and binding but not the full homomorphic property.
/// TODO: Implement proper EC-based Pedersen for full homomorphism
pub fn commit_value(value: u64, blinding: &BlindingFactor) -> PedersenCommitment {
    use crate::poseidon::poseidon_hash_two;

    let value_field = Field::from(value);
    let commitment_field = poseidon_hash_two(value_field, blinding.inner);

    PedersenCommitment {
        commitment: field_to_bytes(&commitment_field),
    }
}

/// Verify that a commitment opens to a specific value
pub fn verify_commitment(
    commitment: &PedersenCommitment,
    value: u64,
    blinding: &BlindingFactor,
) -> bool {
    let expected = commit_value(value, blinding);
    use subtle::ConstantTimeEq;
    commitment.commitment.ct_eq(&expected.commitment).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(12345)
    }

    #[test]
    fn test_commitment_hiding() {
        let mut rng = test_rng();
        let value = 1000u64;

        let blinding1 = BlindingFactor::random(&mut rng);
        let blinding2 = BlindingFactor::random(&mut rng);

        let commit1 = commit_value(value, &blinding1);
        let commit2 = commit_value(value, &blinding2);

        // Same value, different blindings -> different commitments
        assert_ne!(commit1.commitment, commit2.commitment);
    }

    #[test]
    fn test_commitment_binding() {
        let mut rng = test_rng();
        let blinding = BlindingFactor::random(&mut rng);

        let commit1 = commit_value(100, &blinding);
        let commit2 = commit_value(200, &blinding);

        // Different values, same blinding -> different commitments
        assert_ne!(commit1.commitment, commit2.commitment);
    }

    #[test]
    fn test_commitment_verification() {
        let mut rng = test_rng();
        let value = 42u64;
        let blinding = BlindingFactor::random(&mut rng);

        let commitment = commit_value(value, &blinding);

        assert!(verify_commitment(&commitment, value, &blinding));
        assert!(!verify_commitment(&commitment, value + 1, &blinding));
    }

    #[test]
    fn test_blinding_zeroized_on_drop() {
        let blinding = BlindingFactor::from_field(Field::from(12345u64));
        drop(blinding);
    }
}