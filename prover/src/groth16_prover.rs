//! Groth16 proof generation

use transfer_circuit::*;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, Proof};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::rand::thread_rng;
use std::fs::File;
use std::path::Path;

/// Generate a transfer proof
pub fn prove_transfer(
    input_notes: &[Note],
    output_notes: &[Note],
    secret_key: &Fr,
    pk: &ProvingKey<Bn254>,
) -> Result<(Proof<Bn254>, TransferPublicInputs), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();
    
    // Build circuit witness
    let circuit = build_transfer_circuit(input_notes, output_notes, secret_key)?;
    
    // Extract public inputs
    let public_inputs = TransferPublicInputs {
        merkle_root: circuit.merkle_root,
        nullifiers: circuit.nullifiers.clone(),
        output_commitments: circuit.output_commitments.clone(),
        asset_id: circuit.asset_id,
        fee_commitment: circuit.fee_commitment,
    };
    
    // Generate proof
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)?;
    
    Ok((proof, public_inputs))
}

/// Build circuit from notes
fn build_transfer_circuit(
    input_notes: &[Note],
    output_notes: &[Note],
    secret_key: &Fr,
) -> Result<TransferCircuit, Box<dyn std::error::Error>> {
    // Compute public inputs
    let merkle_root = compute_merkle_root(input_notes)?;
    
    let nullifiers: Vec<Fr> = input_notes.iter()
        .map(|note| note.nullifier(*secret_key))
        .collect();
    
    let output_commitments: Vec<Fr> = output_notes.iter()
        .map(|note| note.commitment())
        .collect();
    
    // Simplified: assume all same asset
    let asset_id = input_notes[0].asset_id;
    
    Ok(TransferCircuit {
        input_notes: input_notes.to_vec(),
        output_notes: output_notes.to_vec(),
        merkle_paths: vec![MerklePath::dummy(); input_notes.len()],
        secret_keys: vec![*secret_key; input_notes.len()],
        merkle_root,
        nullifiers,
        output_commitments,
        asset_id,
        fee_commitment: Fr::from(0),
    })
}

/// Compute Merkle root from input notes
fn compute_merkle_root(notes: &[Note]) -> Result<Fr, Box<dyn std::error::Error>> {
    use crypto::poseidon::poseidon_hash;
    
    // Simplified: just hash all commitments together
    let commitments: Vec<Fr> = notes.iter().map(|n| n.commitment()).collect();
    Ok(poseidon_hash(&commitments))
}

/// Load proving key from file
pub fn load_proving_key(path: &Path) -> Result<ProvingKey<Bn254>, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let pk = ProvingKey::deserialize_uncompressed(&mut file)?;
    Ok(pk)
}

/// Generate proving/verifying keys (trusted setup)
pub fn setup_groth16_keys(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();
    
    // Use a dummy circuit for setup
    let circuit = TransferCircuit::default();
    
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)?;
    
    // Save keys
    std::fs::create_dir_all(output_dir)?;
    
    let mut pk_file = File::create(output_dir.join("transfer.pk"))?;
    pk.serialize_uncompressed(&mut pk_file)?;
    
    let mut vk_file = File::create(output_dir.join("transfer.vk"))?;
    vk.serialize_uncompressed(&mut vk_file)?;
    
    Ok(())
}

/// Public inputs structure (maps to primitives/zk-types)
pub struct TransferPublicInputs {
    pub merkle_root: Fr,
    pub nullifiers: Vec<Fr>,
    pub output_commitments: Vec<Fr>,
    pub asset_id: Fr,
    pub fee_commitment: Fr,
}