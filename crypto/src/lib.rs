//! Zero Chain Cryptographic Primitives
//!
//! This library provides the cryptographic functions used across:
//! - Circuit witness generation (prover)
//! - Client-side operations (CLI)
//! - Test vectors and debugging
//!
//! CRITICAL: Hash parameters here MUST match the in-circuit implementations
//! in circuits/transfer/, circuits/membership/, etc.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod commitment;
pub mod merkle;
pub mod nullifier;
pub mod poseidon;

// Re-export commonly used types
pub use commitment::NoteCommitment;
pub use merkle::{MerkleTree, MerkleProof, TREE_DEPTH};
pub use nullifier::NullifierDeriver;
pub use poseidon::{PoseidonHasher, Hash256};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_workflow() {
        // Create a note commitment
        let value = 100u64;
        let asset_id = [0u8; 32];
        let blinding = [1u8; 32];
        let owner_key = [2u8; 32];

        let commitment = NoteCommitment::commit(value, &asset_id, &blinding, &owner_key);

        // Compute nullifier
        let nullifier_key = [3u8; 32];
        let nullifier = NullifierDeriver::derive(&nullifier_key, &commitment);

        // Build a Merkle tree
        let tree = MerkleTree::new(&[commitment]);
        let root = tree.root();
        let proof = tree.proof(0);

        // Verify proof
        assert!(MerkleTree::verify_proof(&root, &commitment, &proof));

        println!("Commitment: {}", hex::encode(commitment));
        println!("Nullifier:  {}", hex::encode(nullifier));
        println!("Root:       {}", hex::encode(root));
    }
}