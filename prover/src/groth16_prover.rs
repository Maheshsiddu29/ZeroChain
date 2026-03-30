//! Groth16 TransferCircuit for Zero Chain
//! 
//! Proves a shielded transfer without revealing:
//! - Sender
//! - Receiver  
//! - Amount
//! 
//! Public inputs: Merkle root, nullifiers, output commitments, asset ID

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_bn254::Fr;
use ark_ff::{PrimeField, BigInteger};

// REMOVED: pub mod constraints;
// REMOVED: pub mod witness;
// REMOVED: pub use constraints::*;

/// Maximum inputs per transfer
pub const MAX_INPUTS: usize = 8;

/// Maximum outputs per transfer
pub const MAX_OUTPUTS: usize = 8;

/// Merkle tree depth
pub const TREE_DEPTH: usize = 32;

// ============================================================================
// Native Types
// ============================================================================

/// A note representing value
#[derive(Clone, Debug)]
pub struct Note {
    pub value: u64,
    pub asset_id: Fr,
    pub blinding: Fr,
    pub owner_pubkey: Fr,
}

impl Note {
    /// Compute the commitment for this note
    pub fn commitment(&self) -> Fr {
        use sha2::{Sha256, Digest};
        
        let value_fr = Fr::from(self.value);
        let mut bytes = Vec::new();
        bytes.extend(value_fr.into_bigint().to_bytes_le());
        bytes.extend(self.asset_id.into_bigint().to_bytes_le());
        bytes.extend(self.blinding.into_bigint().to_bytes_le());
        bytes.extend(self.owner_pubkey.into_bigint().to_bytes_le());
        
        let hash = Sha256::digest(&bytes);
        Fr::from_le_bytes_mod_order(&hash)
    }
    
    /// Compute nullifier: H(commitment || secret_key)
    pub fn nullifier(&self, secret_key: Fr) -> Fr {
        use sha2::{Sha256, Digest};
        
        let commitment = self.commitment();
        let mut bytes = Vec::new();
        bytes.extend(commitment.into_bigint().to_bytes_le());
        bytes.extend(secret_key.into_bigint().to_bytes_le());
        
        let hash = Sha256::digest(&bytes);
        Fr::from_le_bytes_mod_order(&hash)
    }
}

/// Merkle authentication path
#[derive(Clone, Debug)]
pub struct MerklePath {
    pub path: Vec<Fr>,
    pub indices: Vec<bool>,
}

// ============================================================================
// Circuit Variable Types (R1CS)
// ============================================================================

/// Note as circuit variables
#[derive(Clone)]
pub struct NoteVar {
    pub value: FpVar<Fr>,
    pub asset_id: FpVar<Fr>,
    pub blinding: FpVar<Fr>,
    pub owner_pubkey: FpVar<Fr>,
}

impl AllocVar<Note, Fr> for NoteVar {
    fn new_variable<T: std::borrow::Borrow<Note>>(
        cs: impl Into<ark_relations::r1cs::Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let note = f()?;
        let note = note.borrow();
        
        let value = FpVar::new_variable(cs.clone(), || Ok(Fr::from(note.value)), mode)?;
        let asset_id = FpVar::new_variable(cs.clone(), || Ok(note.asset_id), mode)?;
        let blinding = FpVar::new_variable(cs.clone(), || Ok(note.blinding), mode)?;
        let owner_pubkey = FpVar::new_variable(cs.clone(), || Ok(note.owner_pubkey), mode)?;
        
        Ok(Self { value, asset_id, blinding, owner_pubkey })
    }
}

/// Merkle path as circuit variables
#[derive(Clone)]
pub struct MerklePathVar {
    pub path: Vec<FpVar<Fr>>,
    pub indices: Vec<Boolean<Fr>>,
}

impl AllocVar<MerklePath, Fr> for MerklePathVar {
    fn new_variable<T: std::borrow::Borrow<MerklePath>>(
        cs: impl Into<ark_relations::r1cs::Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let merkle_path = f()?;
        let merkle_path = merkle_path.borrow();
        
        let path = merkle_path.path.iter()
            .map(|sibling| FpVar::new_variable(cs.clone(), || Ok(*sibling), mode))
            .collect::<Result<Vec<_>, _>>()?;
        
        let indices = merkle_path.indices.iter()
            .map(|&idx| Boolean::new_variable(cs.clone(), || Ok(idx), mode))
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok(Self { path, indices })
    }
}

// ============================================================================
// Circuit Constraint Functions
// ============================================================================

/// Verify a Merkle path and return the computed root
pub fn verify_merkle_path(
    note: &NoteVar,
    path: &MerklePathVar,
) -> Result<FpVar<Fr>, SynthesisError> {
    // Start with the note commitment
    let mut current = compute_commitment(note)?;
    
    // Walk up the tree
    for (sibling, is_right) in path.path.iter().zip(path.indices.iter()) {
        // If is_right, current is on right: H(sibling || current)
        // Else current is on left: H(current || sibling)
        let (left, right) = is_right.select(&(sibling.clone(), current.clone()), &(current.clone(), sibling.clone()))?;
        current = hash_pair(&left, &right)?;
    }
    
    Ok(current)
}

/// Compute commitment from note variables (simplified hash)
pub fn compute_commitment(note: &NoteVar) -> Result<FpVar<Fr>, SynthesisError> {
    // Simplified: just add all fields (in production use Poseidon)
    let sum = &note.value + &note.asset_id + &note.blinding + &note.owner_pubkey;
    Ok(sum)
}

/// Compute nullifier from commitment and secret key
pub fn compute_nullifier(
    commitment: &FpVar<Fr>,
    secret_key: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    // Simplified: add them (in production use Poseidon)
    let nullifier = commitment + secret_key;
    Ok(nullifier)
}

/// Hash two field elements (simplified)
pub fn hash_pair(
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    // Simplified: just add (in production use Poseidon)
    Ok(left + right)
}

/// Sum the values of notes
pub fn sum_values(notes: &[NoteVar]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sum = FpVar::zero();
    for note in notes {
        sum = sum + &note.value;
    }
    Ok(sum)
}

// ============================================================================
// Main Circuit
// ============================================================================

/// A shielded transfer circuit
#[derive(Clone, Debug)]
pub struct TransferCircuit {
    // Private witness
    pub input_notes: Vec<Note>,
    pub merkle_paths: Vec<MerklePath>,
    pub output_notes: Vec<Note>,
    pub secret_keys: Vec<Fr>,
    
    // Public inputs
    pub merkle_root: Fr,
    pub nullifiers: Vec<Fr>,
    pub output_commitments: Vec<Fr>,
    pub asset_id: Fr,
    pub fee_commitment: Fr,
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Convert witness to circuit variables
        let input_notes_var = self.input_notes.iter()
            .map(|note| NoteVar::new_witness(cs.clone(), || Ok(note.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        
        let output_notes_var = self.output_notes.iter()
            .map(|note| NoteVar::new_witness(cs.clone(), || Ok(note.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        
        let merkle_paths_var = self.merkle_paths.iter()
            .map(|path| MerklePathVar::new_witness(cs.clone(), || Ok(path.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        
        let secret_keys_var = self.secret_keys.iter()
            .map(|sk| FpVar::new_witness(cs.clone(), || Ok(*sk)))
            .collect::<Result<Vec<_>, _>>()?;
        
        // Public inputs
        let merkle_root_var = FpVar::new_input(cs.clone(), || Ok(self.merkle_root))?;
        
        let nullifiers_var = self.nullifiers.iter()
            .map(|n| FpVar::new_input(cs.clone(), || Ok(*n)))
            .collect::<Result<Vec<_>, _>>()?;
        
        let output_commitments_var = self.output_commitments.iter()
            .map(|c| FpVar::new_input(cs.clone(), || Ok(*c)))
            .collect::<Result<Vec<_>, _>>()?;
        
        let asset_id_var = FpVar::new_input(cs.clone(), || Ok(self.asset_id))?;
        let _fee_commitment_var = FpVar::new_input(cs.clone(), || Ok(self.fee_commitment))?;
        
        // CONSTRAINT 1: Check input notes exist in Merkle tree
        for (note, path) in input_notes_var.iter().zip(merkle_paths_var.iter()) {
            let computed_root = verify_merkle_path(note, path)?;
            computed_root.enforce_equal(&merkle_root_var)?;
        }
        
        // CONSTRAINT 2: Check nullifiers are correctly derived
        for ((note, sk), expected_nullifier) in input_notes_var.iter()
            .zip(secret_keys_var.iter())
            .zip(nullifiers_var.iter())
        {
            let commitment = compute_commitment(note)?;
            let computed_nullifier = compute_nullifier(&commitment, sk)?;
            computed_nullifier.enforce_equal(expected_nullifier)?;
        }
        
        // CONSTRAINT 3: Check output commitments are correctly computed
        for (note, expected_commitment) in output_notes_var.iter().zip(output_commitments_var.iter()) {
            let computed_commitment = compute_commitment(note)?;
            computed_commitment.enforce_equal(expected_commitment)?;
        }
        
        // CONSTRAINT 4: Check asset ID consistency
        for note in input_notes_var.iter().chain(output_notes_var.iter()) {
            note.asset_id.enforce_equal(&asset_id_var)?;
        }
        
        // CONSTRAINT 5: Balance constraint (inputs = outputs)
        let input_sum = sum_values(&input_notes_var)?;
        let output_sum = sum_values(&output_notes_var)?;
        input_sum.enforce_equal(&output_sum)?;
        
        Ok(())
    }
}

impl Default for TransferCircuit {
    fn default() -> Self {
        Self {
            input_notes: vec![],
            merkle_paths: vec![],
            output_notes: vec![],
            secret_keys: vec![],
            merkle_root: Fr::from(0u64),
            nullifiers: vec![],
            output_commitments: vec![],
            asset_id: Fr::from(0u64),
            fee_commitment: Fr::from(0u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use ark_relations::r1cs::ConstraintSystem;
    
    #[test]
    fn test_circuit_satisfiability() {
        let mut rng = test_rng();
        
        let secret_key = Fr::rand(&mut rng);
        let asset_id = Fr::from(0u64);
        
        let input_note = Note {
            value: 100,
            asset_id,
            blinding: Fr::rand(&mut rng),
            owner_pubkey: Fr::rand(&mut rng),
        };
        
        let output_note = Note {
            value: 100,
            asset_id,
            blinding: Fr::rand(&mut rng),
            owner_pubkey: Fr::rand(&mut rng),
        };
        
        // Compute expected values using simplified circuit logic
        // Circuit uses: commitment = value + asset_id + blinding + owner_pubkey
        let input_value_fr = Fr::from(input_note.value);
        let input_commitment = input_value_fr + input_note.asset_id + input_note.blinding + input_note.owner_pubkey;
        
        // Circuit uses: nullifier = commitment + secret_key
        let nullifier = input_commitment + secret_key;
        
        let output_value_fr = Fr::from(output_note.value);
        let output_commitment = output_value_fr + output_note.asset_id + output_note.blinding + output_note.owner_pubkey;
        
        let circuit = TransferCircuit {
            input_notes: vec![input_note],
            output_notes: vec![output_note],
            merkle_paths: vec![MerklePath {
                path: vec![],
                indices: vec![],
            }],
            secret_keys: vec![secret_key],
            merkle_root: input_commitment, // With empty path, root = commitment
            nullifiers: vec![nullifier],
            output_commitments: vec![output_commitment],
            asset_id,
            fee_commitment: Fr::from(0u64),
        };
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        println!("Number of constraints: {}", cs.num_constraints());
        println!("Is satisfied: {:?}", cs.is_satisfied());
        
        if !cs.is_satisfied().unwrap() {
            println!("Which constraints failed: {:?}", cs.which_is_unsatisfied());
        }
        
        assert!(cs.is_satisfied().unwrap(), "Constraints not satisfied!");
    }
}