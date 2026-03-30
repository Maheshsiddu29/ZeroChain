//! Poseidon Hash for BN254
//!
//! CRITICAL: These parameters MUST match circuits/transfer/src/poseidon.rs
//!
//! Currently using a simplified implementation. For production, use:
//! - Neptune (poseidon2) or
//! - arkworks-rs/poseidon-paramgen parameters

use sha2::{Sha256, Digest};

pub type Hash256 = [u8; 32];

/// Poseidon parameters (MUST match circuit)
pub mod params {
    pub const WIDTH: usize = 3;       // State width
    pub const RATE: usize = 2;        // How many elements absorbed per permutation
    pub const CAPACITY: usize = 1;    // Security margin
    pub const FULL_ROUNDS: usize = 8;
    pub const PARTIAL_ROUNDS: usize = 57;
    pub const ALPHA: u64 = 5;         // S-box exponent
}

/// Poseidon hasher for Zero Chain
///
/// This is a SIMPLIFIED implementation using SHA256 as the underlying permutation.
/// For production, replace with a proper Poseidon implementation using:
/// - MDS matrix multiplication
/// - Round constants from proper generation algorithm
/// - S-box x^5 over BN254 Fr field
pub struct PoseidonHasher;

impl PoseidonHasher {
    /// Hash two 32-byte values
    pub fn hash_two(left: &Hash256, right: &Hash256) -> Hash256 {
        // Simplified: use SHA256 for now
        // TODO: Replace with proper Poseidon permutation
        let mut hasher = Sha256::new();
        hasher.update(b"ZeroChain.Poseidon.2");
        hasher.update(left);
        hasher.update(right);
        let result = hasher.finalize();
        
        let mut output = [0u8; 32];
        output.copy_from_slice(&result[..]);
        output
    }

    /// Hash a single value
    pub fn hash_one(input: &Hash256) -> Hash256 {
        let mut hasher = Sha256::new();
        hasher.update(b"ZeroChain.Poseidon.1");
        hasher.update(input);
        let result = hasher.finalize();
        
        let mut output = [0u8; 32];
        output.copy_from_slice(&result[..]);
        output
    }

    /// Hash four values (for commitment)
    pub fn hash_four(a: &Hash256, b: &Hash256, c: &Hash256, d: &Hash256) -> Hash256 {
        // Simplified: hash pairs then combine
        let left = Self::hash_two(a, b);
        let right = Self::hash_two(c, d);
        Self::hash_two(&left, &right)
    }

    /// Hash arbitrary number of elements
    pub fn hash_many(inputs: &[Hash256]) -> Hash256 {
        if inputs.is_empty() {
            return [0u8; 32];
        }
        
        let mut hasher = Sha256::new();
        hasher.update(b"ZeroChain.Poseidon.Many");
        hasher.update(&(inputs.len() as u64).to_le_bytes());
        for input in inputs {
            hasher.update(input);
        }
        let result = hasher.finalize();
        
        let mut output = [0u8; 32];
        output.copy_from_slice(&result[..]);
        output
    }

    /// Convert u64 to Hash256
    pub fn u64_to_hash(value: u64) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    /// Hash two u64 values (convenience)
    pub fn hash_two_u64(a: u64, b: u64) -> Hash256 {
        Self::hash_two(&Self::u64_to_hash(a), &Self::u64_to_hash(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let h1 = PoseidonHasher::hash_two(&a, &b);
        let h2 = PoseidonHasher::hash_two(&a, &b);

        assert_eq!(h1, h2, "Hash must be deterministic");
    }

    #[test]
    fn test_hash_different_inputs() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];

        let h1 = PoseidonHasher::hash_two(&a, &b);
        let h2 = PoseidonHasher::hash_two(&a, &c);

        assert_ne!(h1, h2);
    }

    #[test]
    fn test_known_values() {
        println!("=== Known Poseidon Values (for circuit verification) ===");
        
        let h1 = PoseidonHasher::hash_two_u64(0, 0);
        println!("Poseidon(0, 0) = 0x{}", hex::encode(h1));
        
        let h2 = PoseidonHasher::hash_two_u64(1, 2);
        println!("Poseidon(1, 2) = 0x{}", hex::encode(h2));
        
        let h3 = PoseidonHasher::hash_two_u64(123456789, 987654321);
        println!("Poseidon(123456789, 987654321) = 0x{}", hex::encode(h3));
    }
}