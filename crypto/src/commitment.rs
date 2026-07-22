//! Note commitment scheme
//!
//! cm = Poseidon_t5(owner_pubkey, value, asset_id, blinding)
//!
//! Matches `Note::commitment()` in `circuits/transfer/src/lib.rs` exactly.
//! Available in no_std when the `poseidon` feature is enabled.

#[cfg(any(feature = "poseidon", feature = "std"))]
use crate::poseidon::{PoseidonHasher, Hash256};

/// Note commitment generator
pub struct NoteCommitment;

/// Commit is available in no_std (WASM runtime) with the `poseidon` feature.
#[cfg(any(feature = "poseidon", feature = "std"))]
impl NoteCommitment {
    /// Compute commitment: Poseidon_t5(owner_pubkey, value, asset_id, blinding)
    pub fn commit(
        value: u64,
        asset_id: &Hash256,
        blinding: &Hash256,
        owner_pubkey: &Hash256,
    ) -> Hash256 {
        let value_bytes = PoseidonHasher::u64_to_hash(value);
        // Canonical ordering: owner_pubkey, value, asset_id, blinding — matches circuit
        PoseidonHasher::hash_four(owner_pubkey, &value_bytes, asset_id, blinding)
    }
}

/// Verify uses subtle::ConstantTimeEq which requires std.
#[cfg(feature = "std")]
impl NoteCommitment {
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

#[cfg(feature = "std")]
fn constant_time_eq(a: &Hash256, b: &Hash256) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(feature = "std")]
pub fn random_blinding() -> Hash256 {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut blinding = [0u8; 32];
    rng.fill_bytes(&mut blinding);
    blinding
}

/// Compute cm = Poseidon_t5(owner_pubkey, amount, asset_id, blinding) — the canonical
/// note commitment used by both the shield extrinsic (on-chain) and the transfer circuit
/// (`Note::commitment()` in `circuits/transfer/src/lib.rs`).
///
/// `amount` is `u64` to match `Note.value: u64`.  The shield extrinsic enforces
/// `amount <= u64::MAX` before calling this.
///
/// Available in no_std (WASM runtime) when the `poseidon` feature is enabled.
#[cfg(any(feature = "poseidon", feature = "std"))]
pub fn note_commitment(
    owner_pubkey: &[u8; 32],
    amount: u64,
    asset_id: &[u8; 32],
    blinding: &[u8; 32],
) -> [u8; 32] {
    NoteCommitment::commit(amount, asset_id, blinding, owner_pubkey)
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

    /// note_commitment free-fn must produce the same result as NoteCommitment::commit
    /// with the same inputs in the canonical order.
    #[test]
    fn note_commitment_free_fn_matches_commit() {
        let owner = [0xAAu8; 32];
        let amount = 1234u64;
        let asset_id = [0u8; 32];
        let blinding = [0xBBu8; 32];

        let via_method = NoteCommitment::commit(amount, &asset_id, &blinding, &owner);
        let via_fn = note_commitment(&owner, amount, &asset_id, &blinding);

        assert_eq!(via_method, via_fn);
    }
}
