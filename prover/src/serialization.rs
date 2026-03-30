//! Serialize proofs to match primitives/zk-types format

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::Proof;
use ark_serialize::CanonicalSerialize;
use zk_types::{Groth16Proof, TransferPublicInputs as ZkTypesTransferInputs, ProofSubmission, Hash256};
use std::path::Path;
use std::fs::File;
use std::io::Write;

use super::groth16_prover::TransferPublicInputs;

/// Convert arkworks proof to zk-types format
pub fn serialize_transfer_proof(
    proof: Proof<Bn254>,
    public_inputs: TransferPublicInputs,
) -> Result<ProofSubmission, Box<dyn std::error::Error>> {
    // Serialize proof points to bytes
    let mut a_bytes = [0u8; 64];
    proof.a.serialize_uncompressed(&mut a_bytes[..])?;
    
    let mut b_bytes = [0u8; 128];
    proof.b.serialize_uncompressed(&mut b_bytes[..])?;
    
    let mut c_bytes = [0u8; 64];
    proof.c.serialize_uncompressed(&mut c_bytes[..])?;
    
    let groth16_proof = Groth16Proof {
        a: a_bytes,
        b: b_bytes,
        c: c_bytes,
    };
    
    // Convert public inputs to Hash256
    let zk_inputs = ZkTypesTransferInputs {
        merkle_root: field_to_hash256(&public_inputs.merkle_root),
        nullifiers: public_inputs.nullifiers.iter().map(field_to_hash256).collect(),
        output_commitments: public_inputs.output_commitments.iter().map(field_to_hash256).collect(),
        asset_id: field_to_hash256(&public_inputs.asset_id),
        fee_commitment: field_to_hash256(&public_inputs.fee_commitment),
    };
    
    Ok(ProofSubmission::ShieldedTransfer {
        proof: groth16_proof,
        inputs: zk_inputs,
    })
}

/// Convert field element to 32-byte hash
fn field_to_hash256(field: &Fr) -> Hash256 {
    let mut bytes = [0u8; 32];
    field.serialize_uncompressed(&mut bytes[..]).unwrap();
    bytes
}

/// Save proof submission as JSON
pub fn save_proof_submission(
    path: &Path,
    submission: &ProofSubmission,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(submission)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

/// Helper functions for loading notes from JSON
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct NoteJson {
    value: u64,
    asset_id: String,
    blinding: String,
    owner_pubkey: String,
}

pub fn load_notes(path: &Path) -> Result<Vec<transfer_circuit::Note>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let notes_json: Vec<NoteJson> = serde_json::from_reader(file)?;
    
    let notes = notes_json.iter()
        .map(|nj| {
            Ok(transfer_circuit::Note {
                value: nj.value,
                asset_id: hex_to_field(&nj.asset_id)?,
                blinding: hex_to_field(&nj.blinding)?,
                owner_pubkey: hex_to_field(&nj.owner_pubkey)?,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    
    Ok(notes)
}

pub fn hex_to_field_element(hex: &str) -> Result<Fr, Box<dyn std::error::Error>> {
    hex_to_field(hex)
}

fn hex_to_field(hex_str: &str) -> Result<Fr, Box<dyn std::error::Error>> {
    let hex_clean = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(hex_clean)?;
    
    use ark_serialize::CanonicalDeserialize;
    let field = Fr::deserialize_uncompressed(&bytes[..])?;
    Ok(field)
}