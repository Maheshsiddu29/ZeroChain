//! Nullifier generation for double-spend prevention
//!
//! nullifier = Poseidon(secret, leaf_index)

//#![cfg_attr(not(feature = "std"), no_std)]

use ark_bn254::Fr;
use ark_serialize::CanonicalDeserialize;
use crate::poseidon::PoseidonHasher;

/// A nullifier that prevents double-spending
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nullifier {
    pub value: Fr,
}

impl Nullifier {
    /// Create a nullifier from a secret and leaf index
    pub fn new(secret: Fr, leaf_index: u64) -> Self {
        let hasher = PoseidonHasher::new();
        let index_field = Fr::from(leaf_index);
        let value = hasher.hash_two(secret, index_field);
        Self { value }
    }

    /// Create a nullifier from a secret and a field element
    pub fn from_fields(secret: Fr, domain_separator: Fr) -> Self {
        let hasher = PoseidonHasher::new();
        let value = hasher.hash_two(secret, domain_separator);
        Self { value }
    }

    /// Generate a random nullifier (for testing)
    #[cfg(feature = "std")]
    pub fn random() -> Self {
        use ark_std::rand::Rng;
        let mut rng = ark_std::test_rng();
        let value = Fr::from(rng.gen::<u64>());
        Self { value }
    }

    /// Get the nullifier as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        use ark_serialize::CanonicalSerialize;
        let mut buf = [0u8; 32];
        self.value
            .serialize_compressed(&mut buf[..])
            .expect("serialization failed");
        buf
    }

    /// Create a nullifier from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Fr::deserialize_compressed(bytes)
            .ok()
            .map(|value| Self { value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_deterministic() {
        let secret = Fr::from(12345u64);
        let n1 = Nullifier::new(secret, 0);
        let n2 = Nullifier::new(secret, 0);
        assert_eq!(n1, n2, "Same inputs should produce same nullifier");
    }

    #[test]
    fn test_nullifier_different_index() {
        let secret = Fr::from(12345u64);
        let n1 = Nullifier::new(secret, 0);
        let n2 = Nullifier::new(secret, 1);
        assert_ne!(n1, n2, "Different index should produce different nullifier");
    }

    #[test]
    fn test_nullifier_different_secret() {
        let s1 = Fr::from(111u64);
        let s2 = Fr::from(222u64);
        let n1 = Nullifier::new(s1, 0);
        let n2 = Nullifier::new(s2, 0);
        assert_ne!(n1, n2, "Different secret should produce different nullifier");
    }

    #[test]
    fn test_nullifier_serialization() {
        let secret = Fr::from(42u64);
        let n = Nullifier::new(secret, 5);
        let bytes = n.to_bytes();
        let recovered = Nullifier::from_bytes(&bytes).unwrap();
        assert_eq!(n, recovered);
    }
}
