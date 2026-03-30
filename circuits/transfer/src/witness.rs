//! Witness generation helpers

use super::*;
use ark_ff::UniformRand;
use ark_std::rand::Rng;

impl Note {
    /// Create a new random note
    pub fn random<R: Rng>(rng: &mut R, value: u64, asset_id: Fr) -> Self {
        Self {
            value,
            asset_id,
            blinding: Fr::rand(rng),
            owner_pubkey: Fr::rand(rng),
        }
    }

    /// Compute native commitment (MUST MATCH circuit!)
    pub fn commitment(&self) -> Fr {
        // Circuit uses: value + asset_id + blinding + owner_pubkey
        Fr::from(self.value) + self.asset_id + self.blinding + self.owner_pubkey
    }

    /// Compute nullifier (MUST MATCH circuit!)
    pub fn nullifier(&self, secret_key: Fr) -> Fr {
        // Circuit uses: commitment + secret_key
        let commitment = self.commitment();
        commitment + secret_key
    }
}

impl MerklePath {
    /// Create dummy path (all zeros) for testing
    pub fn dummy() -> Self {
        Self {
            path: vec![Fr::from(0); TREE_DEPTH],
            indices: vec![false; TREE_DEPTH],
        }
    }
}

impl TransferCircuit {
    /// Create a valid test circuit (1-in-1-out)
    pub fn test_circuit() -> Self {
        use ark_std::test_rng;
        let mut rng = test_rng();

        let secret_key = Fr::rand(&mut rng);
        let asset_id = Fr::from(0);

        let input_note = Note::random(&mut rng, 100, asset_id);
        let input_nullifier = input_note.nullifier(secret_key);

        let output_note = Note::random(&mut rng, 100, asset_id);
        let output_commitment = output_note.commitment();

        // With empty merkle path, root = commitment
        let merkle_root = input_note.commitment();

        Self {
            input_notes: vec![input_note],
            output_notes: vec![output_note],
            merkle_paths: vec![MerklePath {
                path: vec![],  // Empty path
                indices: vec![],
            }],
            secret_keys: vec![secret_key],
            merkle_root,
            nullifiers: vec![input_nullifier],
            output_commitments: vec![output_commitment],
            asset_id,
            fee_commitment: Fr::from(0),
        }
    }
}
