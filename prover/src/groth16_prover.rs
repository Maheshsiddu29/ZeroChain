//! Groth16 prover for shielded transfers

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_ff::PrimeField;
use std::path::Path;
use anyhow::{Result, Context};

use transfer_circuit::{TransferCircuit, Note, MerklePath};

/// Get a cryptographically secure RNG
fn get_rng() -> rand::rngs::ThreadRng {
    rand::thread_rng()
}

/// Create a dummy circuit with the same shape as a real 1-in-1-out transfer.
///
/// CRITICAL: The dummy circuit used for setup MUST have the same number of
/// constraints as the real circuit. This means same number of input notes,
/// output notes, and merkle path lengths.
fn dummy_circuit_1in_1out() -> TransferCircuit {
    let asset_id = Fr::from(0u64);
    let blinding = Fr::from(1u64);
    let owner = Fr::from(2u64);
    let secret_key = Fr::from(3u64);

    let input_note = Note {
        value: 100,
        asset_id,
        blinding,
        owner_pubkey: owner,
    };

    let output_note = Note {
        value: 100,
        asset_id,
        blinding: Fr::from(4u64),
        owner_pubkey: Fr::from(5u64),
    };

    // Compute values matching circuit logic
    let input_value_fr = Fr::from(input_note.value);
    let input_commitment = input_value_fr + input_note.asset_id + input_note.blinding + input_note.owner_pubkey;
    let nullifier = input_commitment + secret_key;

    let output_value_fr = Fr::from(output_note.value);
    let output_commitment = output_value_fr + output_note.asset_id + output_note.blinding + output_note.owner_pubkey;

    TransferCircuit {
        input_notes: vec![input_note],
        output_notes: vec![output_note],
        merkle_paths: vec![MerklePath { path: vec![], indices: vec![] }],
        secret_keys: vec![secret_key],
        merkle_root: input_commitment, // With empty path, root = commitment
        nullifiers: vec![nullifier],
        output_commitments: vec![output_commitment],
        asset_id,
        fee_commitment: Fr::from(0u64),
    }
}

/// Generate proving and verifying keys for a 1-input-1-output transfer circuit
pub fn setup() -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    log::info!("Running trusted setup for TransferCircuit (1-in, 1-out)...");

    let dummy_circuit = dummy_circuit_1in_1out();

    let mut rng = get_rng();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("Setup failed: {:?}", e))?;

    log::info!("Setup complete");
    Ok((pk, vk))
}

/// Generate a proof for a shielded transfer
pub fn prove(
    pk: &ProvingKey<Bn254>,
    circuit: TransferCircuit,
) -> Result<Proof<Bn254>> {
    log::info!("Generating transfer proof...");
    log::info!("  Inputs: {}, Outputs: {}", circuit.input_notes.len(), circuit.output_notes.len());

    let mut rng = get_rng();
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {:?}", e))?;

    log::info!("Proof generated successfully");
    Ok(proof)
}

/// Verify a transfer proof
pub fn verify(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr],
) -> Result<bool> {
    log::info!("Verifying transfer proof with {} public inputs...", public_inputs.len());

    let pvk = Groth16::<Bn254>::process_vk(vk)
        .map_err(|e| anyhow::anyhow!("Failed to process VK: {:?}", e))?;
    let result = Groth16::<Bn254>::verify_with_processed_vk(&pvk, public_inputs, proof)
        .map_err(|e| anyhow::anyhow!("Verification error: {:?}", e))?;

    log::info!("Verification result: {}", result);
    Ok(result)
}

/// Save proving key to file
pub fn save_proving_key(pk: &ProvingKey<Bn254>, path: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    pk.serialize_uncompressed(&mut bytes)
        .map_err(|e| anyhow::anyhow!("Failed to serialize proving key: {:?}", e))?;

    std::fs::write(path, &bytes).context("Failed to write proving key")?;
    log::info!("Proving key saved to {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

/// Load proving key from file
pub fn load_proving_key(path: &Path) -> Result<ProvingKey<Bn254>> {
    let bytes = std::fs::read(path).context("Failed to read proving key file")?;
    log::info!("Loading proving key from {} ({} bytes)", path.display(), bytes.len());

    let pk = ProvingKey::deserialize_uncompressed_unchecked(&bytes[..])
        .map_err(|e| anyhow::anyhow!("Failed to deserialize proving key: {:?}", e))?;

    log::info!("Proving key loaded");
    Ok(pk)
}

/// Save verifying key to file
pub fn save_verifying_key(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    vk.serialize_uncompressed(&mut bytes)
        .map_err(|e| anyhow::anyhow!("Failed to serialize verifying key: {:?}", e))?;

    std::fs::write(path, &bytes).context("Failed to write verifying key")?;
    log::info!("Verifying key saved to {} ({} bytes)", path.display(), bytes.len());
    Ok(())
}

/// Load verifying key from file
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey<Bn254>> {
    let bytes = std::fs::read(path).context("Failed to read verifying key file")?;
    log::info!("Loading verifying key from {} ({} bytes)", path.display(), bytes.len());

    let vk = VerifyingKey::deserialize_uncompressed_unchecked(&bytes[..])
        .map_err(|e| anyhow::anyhow!("Failed to deserialize verifying key: {:?}", e))?;

    log::info!("Verifying key loaded");
    Ok(vk)
}

/// Convert arkworks Proof to zk-types Groth16Proof format
pub fn proof_to_zk_types(proof: &Proof<Bn254>) -> Result<zk_types::Groth16Proof> {
    let mut a_bytes = Vec::new();
    proof.a.serialize_uncompressed(&mut a_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to serialize proof.a: {:?}", e))?;

    let mut b_bytes = Vec::new();
    proof.b.serialize_uncompressed(&mut b_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to serialize proof.b: {:?}", e))?;

    let mut c_bytes = Vec::new();
    proof.c.serialize_uncompressed(&mut c_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to serialize proof.c: {:?}", e))?;

    log::debug!("Proof point sizes: a={}, b={}, c={}", a_bytes.len(), b_bytes.len(), c_bytes.len());

    let a: [u8; zk_types::G1_UNCOMPRESSED_SIZE] = a_bytes.try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("proof.a wrong size: {} (expected {})", v.len(), zk_types::G1_UNCOMPRESSED_SIZE))?;

    let b: [u8; zk_types::G2_UNCOMPRESSED_SIZE] = b_bytes.try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("proof.b wrong size: {} (expected {})", v.len(), zk_types::G2_UNCOMPRESSED_SIZE))?;

    let c: [u8; zk_types::G1_UNCOMPRESSED_SIZE] = c_bytes.try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("proof.c wrong size: {} (expected {})", v.len(), zk_types::G1_UNCOMPRESSED_SIZE))?;

    Ok(zk_types::Groth16Proof { a, b, c })
}

/// Convert zk-types Groth16Proof back to arkworks Proof
pub fn zk_types_to_proof(zk_proof: &zk_types::Groth16Proof) -> Result<Proof<Bn254>> {
    let a = G1Affine::deserialize_uncompressed_unchecked(&zk_proof.a[..])
        .map_err(|e| anyhow::anyhow!("Failed to deserialize proof.a: {:?}", e))?;

    let b = G2Affine::deserialize_uncompressed_unchecked(&zk_proof.b[..])
        .map_err(|e| anyhow::anyhow!("Failed to deserialize proof.b: {:?}", e))?;

    let c = G1Affine::deserialize_uncompressed_unchecked(&zk_proof.c[..])
        .map_err(|e| anyhow::anyhow!("Failed to deserialize proof.c: {:?}", e))?;

    Ok(Proof { a, b, c })
}

/// Build a TransferCircuit from witness JSON
pub fn build_circuit_from_witness(witness_json: &serde_json::Value) -> Result<TransferCircuit> {
    let input_notes_json = witness_json["input_notes"].as_array()
        .ok_or_else(|| anyhow::anyhow!("Missing input_notes"))?;

    let output_notes_json = witness_json["output_notes"].as_array()
        .ok_or_else(|| anyhow::anyhow!("Missing output_notes"))?;

    if input_notes_json.len() != 1 || output_notes_json.len() != 1 {
        anyhow::bail!(
            "Currently only 1-input-1-output transfers are supported. Got {} inputs, {} outputs",
            input_notes_json.len(),
            output_notes_json.len()
        );
    }

    let mut input_notes = Vec::new();
    let mut merkle_paths = Vec::new();
    let mut secret_keys = Vec::new();
    let mut nullifiers = Vec::new();

    for note_json in input_notes_json {
        let value: u64 = note_json["value"].as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| note_json["value"].as_u64())
            .ok_or_else(|| anyhow::anyhow!("Invalid value"))?;

        let asset_id = hex_to_fr(note_json["asset_id"].as_str().unwrap_or("0x0"))?;
        let blinding = hex_to_fr(note_json["blinding"].as_str().unwrap_or("0x0"))?;
        let nullifier_key = hex_to_fr(note_json["nullifier_key"].as_str().unwrap_or("0x0"))?;
        let owner_pubkey = hex_to_fr(note_json["owner_pubkey"].as_str().unwrap_or("0x0"))?;

        let note = Note {
            value,
            asset_id,
            blinding,
            owner_pubkey,
        };

        // Compute nullifier using circuit logic (commitment + secret_key)
        let value_fr = Fr::from(value);
        let commitment = value_fr + asset_id + blinding + owner_pubkey;
        let nullifier = commitment + nullifier_key;

        input_notes.push(note);
        secret_keys.push(nullifier_key);
        nullifiers.push(nullifier);

        // Parse Merkle path
        let path_json = note_json["merkle_path"].as_array()
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| hex_to_fr(s).ok())
                .collect::<Vec<_>>())
            .unwrap_or_default();

        let indices_json = note_json["merkle_indices"].as_array()
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_u64())
                .map(|i| i != 0)
                .collect::<Vec<_>>())
            .unwrap_or_default();

        merkle_paths.push(MerklePath {
            path: path_json,
            indices: indices_json,
        });
    }

    let mut output_notes = Vec::new();
    let mut output_commitments = Vec::new();

    for note_json in output_notes_json {
        let value: u64 = note_json["value"].as_str()
            .and_then(|s| s.parse().ok())
            .or_else(|| note_json["value"].as_u64())
            .ok_or_else(|| anyhow::anyhow!("Invalid value"))?;

        let asset_id = hex_to_fr(note_json["asset_id"].as_str().unwrap_or("0x0"))?;
        let blinding = hex_to_fr(note_json["blinding"].as_str().unwrap_or("0x0"))?;
        let recipient_pubkey = hex_to_fr(note_json["recipient_pubkey"].as_str().unwrap_or("0x0"))?;

        let note = Note {
            value,
            asset_id,
            blinding,
            owner_pubkey: recipient_pubkey,
        };

        let value_fr = Fr::from(value);
        let commitment = value_fr + asset_id + blinding + recipient_pubkey;

        output_notes.push(note);
        output_commitments.push(commitment);
    }

    // Compute merkle root from first input
    let merkle_root = if !input_notes.is_empty() && !merkle_paths.is_empty() {
        let note = &input_notes[0];
        let path = &merkle_paths[0];
        let value_fr = Fr::from(note.value);
        let mut current = value_fr + note.asset_id + note.blinding + note.owner_pubkey;

        for (sibling, &is_right) in path.path.iter().zip(path.indices.iter()) {
            if is_right {
                current = *sibling + current;
            } else {
                current = current + *sibling;
            }
        }
        current
    } else {
        Fr::from(0u64)
    };

    let asset_id = if !input_notes.is_empty() {
        input_notes[0].asset_id
    } else {
        Fr::from(0u64)
    };

    Ok(TransferCircuit {
        input_notes,
        merkle_paths,
        output_notes,
        secret_keys,
        merkle_root,
        nullifiers,
        output_commitments,
        asset_id,
        fee_commitment: Fr::from(0u64),
    })
}

/// Helper to convert hex string to Fr
fn hex_to_fr(hex: &str) -> Result<Fr> {
    let hex_clean = hex.trim_start_matches("0x");

    if hex_clean.is_empty() || hex_clean == "0" {
        return Ok(Fr::from(0u64));
    }

    let bytes = hex::decode(hex_clean).context("Invalid hex string")?;

    let mut padded = [0u8; 32];
    let len = bytes.len().min(32);
    padded[..len].copy_from_slice(&bytes[..len]);

    Ok(Fr::from_le_bytes_mod_order(&padded))
}

/// Extract public inputs from a circuit for verification
pub fn extract_public_inputs(circuit: &TransferCircuit) -> Vec<Fr> {
    let mut inputs = Vec::new();

    // Order MUST match the circuit's new_input allocation order in generate_constraints:
    // 1. merkle_root
    inputs.push(circuit.merkle_root);
    // 2. each nullifier
    inputs.extend(circuit.nullifiers.iter().copied());
    // 3. each output_commitment
    inputs.extend(circuit.output_commitments.iter().copied());
    // 4. asset_id
    inputs.push(circuit.asset_id);
    // 5. fee_commitment
    inputs.push(circuit.fee_commitment);

    inputs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_prove_verify_cycle() {
        // Setup with dummy 1-in-1-out
        let (pk, vk) = setup().unwrap();

        // Build a real 1-in-1-out circuit with same shape
        let witness_json: serde_json::Value = serde_json::from_str(r#"{
            "input_notes": [{
                "value": "42",
                "asset_id": "0x0",
                "blinding": "0x07",
                "nullifier_key": "0x0b",
                "owner_pubkey": "0x0"
            }],
            "output_notes": [{
                "value": "42",
                "asset_id": "0x0",
                "blinding": "0x0d",
                "recipient_pubkey": "0x11"
            }]
        }"#).unwrap();

        let circuit = build_circuit_from_witness(&witness_json).unwrap();
        let public_inputs = extract_public_inputs(&circuit);

        let proof = prove(&pk, circuit).unwrap();
        let valid = verify(&vk, &proof, &public_inputs).unwrap();
        assert!(valid, "Proof must verify");
    }

    #[test]
    fn test_proof_to_zk_types_roundtrip() {
        let (pk, _vk) = setup().unwrap();
        let circuit = dummy_circuit_1in_1out();
        let proof = prove(&pk, circuit).unwrap();

        let zk_proof = proof_to_zk_types(&proof).unwrap();
        let proof2 = zk_types_to_proof(&zk_proof).unwrap();

        // Verify roundtrip by serializing both
        let mut bytes1 = Vec::new();
        let mut bytes2 = Vec::new();
        proof.serialize_uncompressed(&mut bytes1).unwrap();
        proof2.serialize_uncompressed(&mut bytes2).unwrap();
        assert_eq!(bytes1, bytes2);
    }
}