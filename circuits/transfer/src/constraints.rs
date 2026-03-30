//! Constraint gadgets for the TransferCircuit

use super::*;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use ark_bn254::Fr;

/// Circuit variable for a Note
#[derive(Clone)]
pub struct NoteVar {
    pub value: FpVar<Fr>,
    pub asset_id: FpVar<Fr>,
    pub blinding: FpVar<Fr>,
    pub owner_pubkey: FpVar<Fr>,
}

impl NoteVar {
    pub fn new_witness<F>(
        cs: impl Into<ark_relations::r1cs::Namespace<Fr>>,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<Note, SynthesisError>,
    {
        let cs = cs.into();
        let note = f()?;
        
        Ok(Self {
            value: FpVar::new_witness(cs.clone(), || Ok(Fr::from(note.value)))?,
            asset_id: FpVar::new_witness(cs.clone(), || Ok(note.asset_id))?,
            blinding: FpVar::new_witness(cs.clone(), || Ok(note.blinding))?,
            owner_pubkey: FpVar::new_witness(cs, || Ok(note.owner_pubkey))?,
        })
    }
}

/// Circuit variable for Merkle path
#[derive(Clone)]
pub struct MerklePathVar {
    pub path: Vec<FpVar<Fr>>,
    pub indices: Vec<Boolean<Fr>>,
}

impl MerklePathVar {
    pub fn new_witness<F>(
        cs: impl Into<ark_relations::r1cs::Namespace<Fr>>,
        f: F,
    ) -> Result<Self, SynthesisError>
    where
        F: FnOnce() -> Result<MerklePath, SynthesisError>,
    {
        let cs = cs.into();
        let merkle_path = f()?;
        
        let path = merkle_path.path.iter()
            .map(|hash| FpVar::new_witness(cs.clone(), || Ok(*hash)))
            .collect::<Result<Vec<_>, _>>()?;
        
        let indices = merkle_path.indices.iter()
            .map(|&bit| Boolean::new_witness(cs.clone(), || Ok(bit)))
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok(Self { path, indices })
    }
}

/// Compute note commitment using Poseidon hash
/// commitment = Poseidon(value, asset_id, blinding, owner_pubkey)
pub fn compute_commitment(note: &NoteVar) -> Result<FpVar<Fr>, SynthesisError> {
    // This calls the Poseidon gadget from crypto/ crate
    // For now, simplified as a placeholder
    
    use crypto::poseidon::PoseidonGadget;
    
    let inputs = vec![
        note.value.clone(),
        note.asset_id.clone(),
        note.blinding.clone(),
        note.owner_pubkey.clone(),
    ];
    
    PoseidonGadget::hash(&inputs)
}

/// Compute nullifier = Poseidon(commitment, secret_key)
pub fn compute_nullifier(
    commitment: &FpVar<Fr>,
    secret_key: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    use crypto::poseidon::PoseidonGadget;
    
    let inputs = vec![commitment.clone(), secret_key.clone()];
    PoseidonGadget::hash(&inputs)
}

/// Verify Merkle path from leaf to root
pub fn verify_merkle_path(
    note: &NoteVar,
    path: &MerklePathVar,
) -> Result<FpVar<Fr>, SynthesisError> {
    use crypto::poseidon::PoseidonGadget;
    
    let mut current_hash = compute_commitment(note)?;
    
    for (sibling, is_right) in path.path.iter().zip(path.indices.iter()) {
        // If is_right == true: hash(sibling, current)
        // If is_right == false: hash(current, sibling)
        
        let (left, right) = (
            FpVar::conditionally_select(is_right, sibling, &current_hash)?,
            FpVar::conditionally_select(is_right, &current_hash, sibling)?,
        );
        
        current_hash = PoseidonGadget::hash(&vec![left, right])?;
    }
    
    Ok(current_hash)
}

/// Sum values from notes (for balance check)
pub fn sum_values(notes: &[NoteVar]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sum = FpVar::zero();
    
    for note in notes {
        sum += &note.value;
    }
    
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    
    #[test]
    fn test_commitment_gadget() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        let note = Note {
            value: 42,
            asset_id: Fr::from(0),
            blinding: Fr::from(12345),
            owner_pubkey: Fr::from(67890),
        };
        
        let note_var = NoteVar::new_witness(cs.clone(), || Ok(note)).unwrap();
        let commitment = compute_commitment(&note_var).unwrap();
        
        assert!(cs.is_satisfied().unwrap());
        println!("Commitment computed: {:?}", commitment.value());
    }
}