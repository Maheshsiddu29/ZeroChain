//! Witness generation helpers

use super::*;
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
    
    /// Compute native commitment (outside circuit)
    pub fn commitment(&self) -> Fr {
        use crypto::poseidon::poseidon_hash;
        
        poseidon_hash(&[
            Fr::from(self.value),
            self.asset_id,
            self.blinding,
            self.owner_pubkey,
        ])
    }
    
    /// Compute nullifier (needs secret key)
    pub fn nullifier(&self, secret_key: Fr) -> Fr {
        use crypto::poseidon::poseidon_hash;
        
        let commitment = self.commitment();
        poseidon_hash(&[commitment, secret_key])
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
        use ark_std::rand::thread_rng;
        let mut rng = thread_rng();
        
        let secret_key = Fr::rand(&mut rng);
        let asset_id = Fr::from(0);  // Native token
        
        // Input note
        let input_note = Note::random(&mut rng, 100, asset_id);
        let input_nullifier = input_note.nullifier(secret_key);
        
        // Output note (same value, different owner)
        let output_note = Note::random(&mut rng, 100, asset_id);
        let output_commitment = output_note.commitment();
        
        // Simplified Merkle root (just hash of input commitment)
        use crypto::poseidon::poseidon_hash;
        let merkle_root = poseidon_hash(&[input_note.commitment()]);
        
        Self {
            input_notes: vec![input_note],
            output_notes: vec![output_note],
            merkle_paths: vec![MerklePath::dummy()],
            secret_keys: vec![secret_key],
            merkle_root,
            nullifiers: vec![input_nullifier],
            output_commitments: vec![output_commitment],
            asset_id,
            fee_commitment: Fr::from(0),
        }
    }
}