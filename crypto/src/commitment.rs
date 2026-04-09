//! Note commitment scheme
//!
//! commitment = Poseidon(value, asset_id, blinding, owner_pubkey)

use crate::poseidon::{PoseidonHasher, Hash256};

/// Note commitment generator
pub struct NoteCommitment;

impl NoteCommitment {
    /// Compute commitment from note components
    pub fn commit(
        value: u64,
        asset_id: &Hash256,
        blinding: &Hash256,
        owner_pubkey: &Hash256,
    ) -> Hash256 {
        let value_bytes = PoseidonHasher::u64_to_hash(value);
        PoseidonHasher::hash_four(&value_bytes, asset_id, blinding, owner_pubkey)
    }

    /// Verify a commitment matches expected values
    pub fn verify(
        commitment: &Hash256,
        value: u64,
        asset_id: &Hash256,
        blinding: &Hash256,
        owner_pubkey: &Hash256,
    ) -> bool {
        let computed = Self::commit(value, asset_id, blinding, owner_pubkey);
        constant_time_eq(&computed, commitment)
    }
}

/// Constant-time equality to prevent timing attacks
fn constant_time_eq(a: &Hash256, b: &Hash256) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Generate a random blinding factor
pub fn random_blinding() -> Hash256 {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut blinding = [0u8; 32];
    rng.fill_bytes(&mut blinding);
    blinding
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_deterministic() {
        let value = 100u64;
        let asset_id = [0u8; 32];
        let blinding = [1u8; 32];
        let owner = [2u8; 32];

        let c1 = NoteCommitment::commit(value, &asset_id, &blinding, &owner);
        let c2 = NoteCommitment::commit(value, &asset_id, &blinding, &owner);

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_commitment_different_values() {
        let asset_id = [0u8; 32];
        let blinding = [1u8; 32];
        let owner = [2u8; 32];

        let c1 = NoteCommitment::commit(100, &asset_id, &blinding, &owner);
        let c2 = NoteCommitment::commit(200, &asset_id, &blinding, &owner);

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_commitment_verify() {
        let value = 500u64;
        let asset_id = [0u8; 32];
        let blinding = random_blinding();
        let owner = [99u8; 32];

        let commitment = NoteCommitment::commit(value, &asset_id, &blinding, &owner);
        
        assert!(NoteCommitment::verify(&commitment, value, &asset_id, &blinding, &owner));
        assert!(!NoteCommitment::verify(&commitment, value + 1, &asset_id, &blinding, &owner));
    }
}