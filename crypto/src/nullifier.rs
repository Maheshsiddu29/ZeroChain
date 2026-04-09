//! Nullifier derivation
//!
//! nullifier = Poseidon(nullifier_key, commitment)

use crate::poseidon::{PoseidonHasher, Hash256};

pub struct NullifierDeriver;

impl NullifierDeriver {
    /// Derive a nullifier from secret key and commitment
    pub fn derive(nullifier_key: &Hash256, commitment: &Hash256) -> Hash256 {
        PoseidonHasher::hash_two(nullifier_key, commitment)
    }

    /// Verify a nullifier matches
    pub fn verify(
        nullifier: &Hash256,
        nullifier_key: &Hash256,
        commitment: &Hash256,
    ) -> bool {
        let computed = Self::derive(nullifier_key, commitment);
        constant_time_eq(&computed, nullifier)
    }
}

/// Generate a random nullifier key
pub fn random_nullifier_key() -> Hash256 {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    key
}

fn constant_time_eq(a: &Hash256, b: &Hash256) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_deterministic() {
        let nk = [1u8; 32];
        let cm = [2u8; 32];

        let n1 = NullifierDeriver::derive(&nk, &cm);
        let n2 = NullifierDeriver::derive(&nk, &cm);

        assert_eq!(n1, n2);
    }

    #[test]
    fn test_nullifier_different_keys() {
        let nk1 = [1u8; 32];
        let nk2 = [2u8; 32];
        let cm = [3u8; 32];

        let n1 = NullifierDeriver::derive(&nk1, &cm);
        let n2 = NullifierDeriver::derive(&nk2, &cm);

        assert_ne!(n1, n2);
    }

    #[test]
    fn test_nullifier_verify() {
        let nk = random_nullifier_key();
        let cm = [10u8; 32];

        let nullifier = NullifierDeriver::derive(&nk, &cm);
        assert!(NullifierDeriver::verify(&nullifier, &nk, &cm));

        let wrong_nk = [99u8; 32];
        assert!(!NullifierDeriver::verify(&nullifier, &wrong_nk, &cm));
    }
}