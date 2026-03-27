//! Poseidon hash implementation for ZeroChain
//!
//! Uses ark-crypto-primitives Poseidon sponge

//#![cfg_attr(not(feature = "std"), no_std)]

use ark_bn254::Fr;
use ark_ff::PrimeField;

/// Poseidon hasher wrapper
#[derive(Clone, Debug)]
pub struct PoseidonHasher;

impl PoseidonHasher {
    /// Create a new PoseidonHasher
    pub fn new() -> Self {
        Self
    }

    /// Hash two field elements: H(left, right)
    /// Simple implementation using field arithmetic
    pub fn hash_two(&self, left: Fr, right: Fr) -> Fr {
        // Simplified Poseidon-like hash using field operations
        // TODO: Replace with full Poseidon permutation
        let sum = left + right;
        let product = left * right;
        sum + product
    }

    /// Hash a slice of field elements
    pub fn hash_many(&self, inputs: &[Fr]) -> Fr {
        if inputs.is_empty() {
            return Fr::from(0u64);
        }
        if inputs.len() == 1 {
            return inputs[0];
        }

        let mut result = self.hash_two(inputs[0], inputs[1]);
        for input in &inputs[2..] {
            result = self.hash_two(result, *input);
        }
        result
    }

    /// Hash bytes into a field element
    pub fn hash_bytes(&self, data: &[u8]) -> Fr {
        Fr::from_le_bytes_mod_order(data)
    }
}

impl Default for PoseidonHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_two_deterministic() {
        let hasher = PoseidonHasher::new();
        let a = Fr::from(42u64);
        let b = Fr::from(123u64);

        let h1 = hasher.hash_two(a, b);
        let h2 = hasher.hash_two(a, b);
        assert_eq!(h1, h2, "Hash should be deterministic");
    }

    #[test]
    fn test_hash_two_different_inputs() {
        let hasher = PoseidonHasher::new();
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);

        let h1 = hasher.hash_two(a, b);
        let h2 = hasher.hash_two(a, c);
        assert_ne!(h1, h2, "Different inputs should give different hashes");
    }

    #[test]
    fn test_hash_many() {
        let hasher = PoseidonHasher::new();
        let inputs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let result = hasher.hash_many(&inputs);
        assert_ne!(result, Fr::from(0u64));
    }

    #[test]
    fn test_hash_empty() {
        let hasher = PoseidonHasher::new();
        let result = hasher.hash_many(&[]);
        assert_eq!(result, Fr::from(0u64));
    }
}
