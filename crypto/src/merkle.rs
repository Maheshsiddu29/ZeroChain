//! Poseidon-based Merkle tree

use crate::poseidon::{PoseidonHasher, Hash256};

pub const TREE_DEPTH: usize = 32;
pub const EMPTY_LEAF: Hash256 = [0u8; 32];

/// Sparse Merkle tree
pub struct MerkleTree {
    layers: Vec<Vec<Hash256>>,
    depth: usize,
    num_leaves: usize,
}

impl MerkleTree {
    /// Create tree from leaves
    pub fn new(leaves: &[Hash256]) -> Self {
        if leaves.is_empty() {
            return Self::empty();
        }

        let actual_depth = (leaves.len() as f64).log2().ceil() as usize;
        let capacity = 1usize << actual_depth;

        let mut padded_leaves = leaves.to_vec();
        while padded_leaves.len() < capacity {
            padded_leaves.push(EMPTY_LEAF);
        }

        let mut layers = Vec::new();
        layers.push(padded_leaves);

        for d in 0..actual_depth {
            let prev_layer = &layers[d];
            let mut next_layer = Vec::new();

            for i in (0..prev_layer.len()).step_by(2) {
                let left = &prev_layer[i];
                let right = if i + 1 < prev_layer.len() {
                    &prev_layer[i + 1]
                } else {
                    &EMPTY_LEAF
                };

                let parent = PoseidonHasher::hash_two(left, right);
                next_layer.push(parent);
            }

            layers.push(next_layer);
        }

        Self {
            layers,
            depth: actual_depth,
            num_leaves: leaves.len(),
        }
    }

    /// Empty tree
    pub fn empty() -> Self {
        Self {
            layers: vec![vec![EMPTY_LEAF]],
            depth: 0,
            num_leaves: 0,
        }
    }

    /// Get root
    pub fn root(&self) -> Hash256 {
        if let Some(top) = self.layers.last() {
            if let Some(root) = top.first() {
                return *root;
            }
        }
        EMPTY_LEAF
    }

    /// Get Merkle proof for leaf at index
    pub fn proof(&self, leaf_index: usize) -> MerkleProof {
        assert!(leaf_index < self.num_leaves, "Leaf index out of bounds");

        let mut path = Vec::new();
        let mut indices = Vec::new();
        let mut idx = leaf_index;

        for d in 0..self.depth {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let is_right = idx % 2 == 1;

            let sibling = if sibling_idx < self.layers[d].len() {
                self.layers[d][sibling_idx]
            } else {
                EMPTY_LEAF
            };

            path.push(sibling);
            indices.push(is_right);

            idx /= 2;
        }

        MerkleProof {
            path,
            indices,
            leaf_index,
            root: self.root(),
        }
    }

    /// Verify a Merkle proof
    pub fn verify_proof(
        root: &Hash256,
        leaf: &Hash256,
        proof: &MerkleProof,
    ) -> bool {
        let computed_root = Self::compute_root_from_proof(leaf, &proof.path, &proof.indices);
        &computed_root == root
    }

    /// Compute root from leaf and proof
    pub fn compute_root_from_proof(
        leaf: &Hash256,
        path: &[Hash256],
        indices: &[bool],
    ) -> Hash256 {
        let mut current = *leaf;

        for (sibling, &is_right) in path.iter().zip(indices.iter()) {
            current = if is_right {
                PoseidonHasher::hash_two(sibling, &current)
            } else {
                PoseidonHasher::hash_two(&current, sibling)
            };
        }

        current
    }

    pub fn len(&self) -> usize {
        self.num_leaves
    }

    pub fn is_empty(&self) -> bool {
        self.num_leaves == 0
    }
}

#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub path: Vec<Hash256>,
    pub indices: Vec<bool>,
    pub leaf_index: usize,
    pub root: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let leaf = [42u8; 32];
        let tree = MerkleTree::new(&[leaf]);

        let root = tree.root();
        assert_ne!(root, EMPTY_LEAF);

        let proof = tree.proof(0);
        assert!(MerkleTree::verify_proof(&root, &leaf, &proof));
    }

    #[test]
    fn test_four_leaves() {
        let leaves: Vec<Hash256> = (0..4u8)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i;
                leaf
            })
            .collect();

        let tree = MerkleTree::new(&leaves);
        let root = tree.root();

        for i in 0..4 {
            let proof = tree.proof(i);
            assert!(MerkleTree::verify_proof(&root, &leaves[i], &proof));
        }
    }

    #[test]
    fn test_deterministic_root() {
        let leaves: Vec<Hash256> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];

        let tree1 = MerkleTree::new(&leaves);
        let tree2 = MerkleTree::new(&leaves);

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn print_test_root() {
        let leaves: Vec<Hash256> = (0..4u8)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i;
                leaf
            })
            .collect();

        let tree = MerkleTree::new(&leaves);
        println!("=== Merkle Root (4 leaves) ===");
        println!("Root: 0x{}", hex::encode(tree.root()));
    }
}