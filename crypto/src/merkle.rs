//! Merkle tree implementation using Poseidon hash

//#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;

use ark_bn254::Fr;
use crate::poseidon::PoseidonHasher;

/// Fixed-depth Merkle tree
pub struct MerkleTree {
    pub depth: usize,
    pub leaves: Vec<Fr>,
    pub hasher: PoseidonHasher,
}

/// Proof of membership in the Merkle tree
#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub path: Vec<Fr>,
    pub indices: Vec<bool>, // false = left, true = right
}

impl MerkleTree {
    /// Create a new empty Merkle tree with given depth
    pub fn new(depth: usize) -> Self {
        Self {
            depth,
            leaves: Vec::new(),
            hasher: PoseidonHasher::new(),
        }
    }

    /// Insert a leaf into the tree
    pub fn insert(&mut self, leaf: Fr) {
        let max_leaves = 1usize << self.depth;
        assert!(self.leaves.len() < max_leaves, "Tree is full");
        self.leaves.push(leaf);
    }

    /// Compute the Merkle root
    pub fn root(&self) -> Fr {
        if self.leaves.is_empty() {
            return Fr::from(0u64);
        }

        let mut current_level = self.leaves.clone();

        // Pad to power of 2
        let target_len = 1usize << self.depth;
        current_level.resize(target_len, Fr::from(0u64));

        // Build tree bottom-up
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { Fr::from(0u64) };
                next_level.push(self.hasher.hash_two(left, right));
            }
            current_level = next_level;
        }

        current_level[0]
    }

    /// Generate a Merkle proof for a leaf at the given index
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut current_level = self.leaves.clone();
        let target_len = 1usize << self.depth;
        current_level.resize(target_len, Fr::from(0u64));

        let mut path = Vec::new();
        let mut indices = Vec::new();
        let mut idx = index;

        while current_level.len() > 1 {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = if sibling_idx < current_level.len() {
                current_level[sibling_idx]
            } else {
                Fr::from(0u64)
            };

            path.push(sibling);
            indices.push(idx % 2 != 0); // true if current is right child

            // Compute next level
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { Fr::from(0u64) };
                next_level.push(self.hasher.hash_two(left, right));
            }
            current_level = next_level;
            idx /= 2;
        }

        Some(MerkleProof { path, indices })
    }

    /// Verify a Merkle proof
    pub fn verify(root: Fr, leaf: Fr, proof: &MerkleProof) -> bool {
        let hasher = PoseidonHasher::new();
        let mut current = leaf;

        for (sibling, is_right) in proof.path.iter().zip(proof.indices.iter()) {
            if *is_right {
                current = hasher.hash_two(*sibling, current);
            } else {
                current = hasher.hash_two(current, *sibling);
            }
        }

        current == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::new(4);
        assert_eq!(tree.root(), Fr::from(0u64));
    }

    #[test]
    fn test_single_leaf() {
        let mut tree = MerkleTree::new(2);
        tree.insert(Fr::from(42u64));
        let root = tree.root();
        assert_ne!(root, Fr::from(0u64));
    }

    #[test]
    fn test_merkle_proof() {
        let mut tree = MerkleTree::new(3);
        tree.insert(Fr::from(10u64));
        tree.insert(Fr::from(20u64));
        tree.insert(Fr::from(30u64));

        let root = tree.root();
        let proof = tree.proof(1).unwrap();

        assert!(
            MerkleTree::verify(root, Fr::from(20u64), &proof),
            "Valid proof should verify"
        );
    }

    #[test]
    fn test_invalid_proof() {
        let mut tree = MerkleTree::new(3);
        tree.insert(Fr::from(10u64));
        tree.insert(Fr::from(20u64));

        let root = tree.root();
        let proof = tree.proof(0).unwrap();

        assert!(
            !MerkleTree::verify(root, Fr::from(999u64), &proof),
            "Invalid leaf should not verify"
        );
    }
}