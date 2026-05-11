//! Slashing Circuit for ZK-ORIGIN
//! 
//! Proves: "I (validator with commitment C) signed two conflicting blocks B1 and B2"
//! 
//! Public inputs:
//! - validator_root: Merkle root of validator credentials
//! - nullifier: Unique identifier (prevents double-slashing)
//! - block_hash_1: First block hash
//! - block_hash_2: Second conflicting block hash
//!
//! Private witness:
//! - commitment: Validator credential commitment (hashed secret)
//! - merkle_path: Merkle proof path to validator tree
//! - merkle_indices: Path directions (left/right)
//! - sig_nonce_1: Nonce used when signing block 1
//! - sig_nonce_2: Nonce used when signing block 2
//!
//! Circuit constraints:
//! 1. Prove commitment C is in validator tree → merkle_root
//! 2. Derive nullifier = H(C, epoch) (prevents reuse)
//! 3. Verify both signatures use same commitment but different nonces
//! 4. Verify block hashes are indeed different (equivocation proof)

pub mod chip;
pub mod circuit;

pub use circuit::{SlashingCircuit, SlashingPublicInputs, SlashingError};

pub const VALIDATOR_TREE_DEPTH: usize = 20; // 2^20 ≈ 1M validators

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(VALIDATOR_TREE_DEPTH, 20);
    }
}