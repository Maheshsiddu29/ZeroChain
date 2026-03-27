//! Proof serialization to zk-types format

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::Proof;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use anyhow::{Result, Context};

use zk_types::{
    Groth16Proof, 
    TransferPublicInputs, 
    ProofSubmission,
    ShieldedTransferData,
    Hash256,
    G1_UNCOMPRESSED_SIZE,
    G2_UNCOMPRESSED_SIZE,
};

/// Serialize Groth16 proof to zk-types format
pub fn serialize_transfer_proof(
    proof: Proof<Bn254>,
    merkle_root: Fr,
    nullifiers: Vec<Fr>,
    output_commitments: Vec<Fr>,
    asset_id: Fr,
) -> Result<ProofSubmission> {
    // Serialize proof points
    let mut a_bytes = [0u8; G1_UNCOMPRESSED_SIZE];
    proof.a.serialize_uncompressed(&mut a_bytes[..])
        .context("Failed to serialize proof.a")?;
    
    let mut b_bytes = [0u8; G2_UNCOMPRESSED_SIZE];
    proof.b.serialize_uncompressed(&mut b_bytes[..])
        .context("Failed to serialize proof.b")?;
    
    let mut c_bytes = [0u8; G1_UNCOMPRESSED_SIZE];
    proof.c.serialize_uncompressed(&mut c_bytes[..])
        .context("Failed to serialize proof.c")?;
    
    let groth16_proof = Groth16Proof {
        a: a_bytes,
        b: b_bytes,
        c: c_bytes,
    };
    
    // Convert public inputs
    let public_inputs = TransferPublicInputs {
        merkle_root: field_to_hash256(&merkle_root),
        nullifiers: nullifiers.iter().map(field_to_hash256).collect(),
        output_commitments: output_commitments.iter().map(field_to_hash256).collect(),
        asset_id: field_to_hash256(&asset_id),
        fee_commitment: [0u8; 32], // Simplified
    };
    
    // Use tuple variant with Box
    Ok(ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
        proof: groth16_proof,
        inputs: public_inputs,
    })))
}

/// Convert field element to 32-byte hash
pub fn field_to_hash256(field: &Fr) -> Hash256 {
    let mut bytes = [0u8; 32];
    field.serialize_uncompressed(&mut bytes[..]).unwrap();
    bytes
}

/// Convert 32-byte hash to field element
pub fn bytes_to_field(bytes: &Hash256) -> Result<Fr> {
    Fr::deserialize_uncompressed(&bytes[..])
        .context("Failed to deserialize field element")
}

/// Deserialize Groth16 proof from zk-types format
pub fn deserialize_groth16_proof(proof: &Groth16Proof) -> Result<Proof<Bn254>> {
    let a = G1Affine::deserialize_uncompressed(&proof.a[..])
        .context("Failed to deserialize proof.a")?;
    
    let b = G2Affine::deserialize_uncompressed(&proof.b[..])
        .context("Failed to deserialize proof.b")?;
    
    let c = G1Affine::deserialize_uncompressed(&proof.c[..])
        .context("Failed to deserialize proof.c")?;
    
    Ok(Proof { a, b, c })
}