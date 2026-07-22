//! Witness generation helpers

use super::*;
use ark_std::rand::Rng;
use ark_std::UniformRand;

impl Note {
    /// Create a new random note with a random owner pubkey (for output notes).
    pub fn random<R: Rng>(rng: &mut R, value: u64, asset_id: Fr) -> Self {
        Self {
            value,
            asset_id,
            blinding: Fr::rand(rng),
            owner_pubkey: Fr::rand(rng),
        }
    }

    /// Compute native commitment (outside circuit) — delegates to lib.rs impl.
    pub fn commitment_native(&self) -> Fr {
        self.commitment()
    }
}

impl MerklePath {
    /// Create dummy path (all zeros) for testing — 0-depth tree (root IS commitment).
    pub fn dummy() -> Self {
        Self {
            path: vec![],
            indices: vec![],
        }
    }
}

impl TransferCircuit {
    /// Create a valid test circuit (1-in-1-out, depth-0 Merkle tree).
    ///
    /// Uses a real spend authority: owner_pubkey == Poseidon_t2(sk).
    /// The Merkle root equals the input commitment (empty path, depth-0 tree).
    pub fn test_circuit() -> Self {
        use ark_std::rand::thread_rng;
        let mut rng = thread_rng();

        let secret_key = Fr::rand(&mut rng);
        let asset_id = Fr::from(0u64);

        // Derive owner_pubkey so spend-authority constraint is satisfied.
        let owner_pubkey = poseidon_hash(&[secret_key]);

        let input_note = Note {
            value: 100,
            asset_id,
            blinding: Fr::rand(&mut rng),
            owner_pubkey,
        };

        let input_commitment = input_note.commitment();
        let input_nullifier = input_note.nullifier(secret_key);

        // Output note: same value, independent random owner (no spend-authority check on output).
        let output_note = Note::random(&mut rng, 100, asset_id);
        let output_commitment = output_note.commitment();

        // generate_constraints normalizes all paths to TREE_DEPTH zero-padded entries.
        // Pre-compute the correct root for a leaf at position 0 with all-zero siblings.
        let merkle_root = {
            let mut cur = input_commitment;
            for _ in 0..TREE_DEPTH {
                cur = poseidon_hash(&[cur, Fr::from(0u64)]);
            }
            cur
        };

        Self {
            input_notes: vec![input_note],
            output_notes: vec![output_note],
            merkle_paths: vec![MerklePath::dummy()],
            secret_keys: vec![secret_key],
            merkle_root,
            nullifiers: vec![input_nullifier],
            output_commitments: vec![output_commitment],
            asset_id,
            fee_commitment: Fr::from(0u64),
        }
    }
}
