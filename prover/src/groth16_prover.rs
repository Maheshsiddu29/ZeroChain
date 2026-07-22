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

/// Create a valid dummy circuit for Groth16 setup.
///
/// Uses `TransferCircuit::test_circuit()` which has correct Poseidon-based
/// commitments, nullifiers, and spend authority.  The fixed shape
/// (MAX_INPUTS=8, MAX_OUTPUTS=8, TREE_DEPTH=32) ensures keys generated here
/// are valid for any proving circuit with the same shape.
fn dummy_circuit_1in_1out() -> TransferCircuit {
    TransferCircuit::test_circuit()
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

/// Build a TransferCircuit from witness JSON.
///
/// JSON schema for each input note:
///   { "value": u64, "asset_id": "0x...", "blinding": "0x...",
///     "nullifier_key": "0x...",
///     "owner_pubkey": "0x..." (optional; if zero, derived as Poseidon_t2(nullifier_key)),
///     "merkle_path": ["0x...", ...], "merkle_indices": [0|1, ...] }
///
/// JSON schema for each output note:
///   { "value": u64, "asset_id": "0x...", "blinding": "0x...",
///     "recipient_pubkey": "0x..." }
///
/// Commitments and nullifiers are computed with Poseidon (matching the circuit).
/// The Merkle root is computed by walking the provided path with Poseidon hash_pair.
/// The circuit normalises all paths to TREE_DEPTH inside generate_constraints.
pub fn build_circuit_from_witness(witness_json: &serde_json::Value) -> Result<TransferCircuit> {
    use zc_crypto::poseidon::poseidon_hash;
    use transfer_circuit::TREE_DEPTH;

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

        // If owner_pubkey is missing or zero, derive it from the nullifier_key so
        // the spend-authority constraint (owner_pubkey == Poseidon_t2(sk)) is satisfied.
        let owner_pubkey_raw = hex_to_fr(note_json["owner_pubkey"].as_str().unwrap_or("0x0"))?;
        let owner_pubkey = if owner_pubkey_raw == Fr::from(0u64) {
            poseidon_hash(&[nullifier_key])
        } else {
            owner_pubkey_raw
        };

        let note = Note { value, asset_id, blinding, owner_pubkey };

        // Commitment and nullifier via Poseidon (matching Note::commitment / Note::nullifier)
        let nullifier = note.nullifier(nullifier_key);

        input_notes.push(note);
        secret_keys.push(nullifier_key);
        nullifiers.push(nullifier);

        // Parse Merkle path
        let path_vec = note_json["merkle_path"].as_array()
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| hex_to_fr(s).ok())
                .collect::<Vec<_>>())
            .unwrap_or_default();

        let indices_vec = note_json["merkle_indices"].as_array()
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_u64())
                .map(|i| i != 0)
                .collect::<Vec<_>>())
            .unwrap_or_default();

        merkle_paths.push(MerklePath { path: path_vec, indices: indices_vec });
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

        let note = Note { value, asset_id, blinding, owner_pubkey: recipient_pubkey };
        let commitment = note.commitment();

        output_notes.push(note);
        output_commitments.push(commitment);
    }

    // Compute the Merkle root.  The circuit pads paths to exactly TREE_DEPTH, so
    // we replicate that: start from the leaf commitment and hash up TREE_DEPTH levels
    // (using the provided siblings for non-empty positions, zero for the rest).
    let merkle_root = if !input_notes.is_empty() {
        let note = &input_notes[0];
        let path = &merkle_paths[0];
        let mut cur = note.commitment();
        for i in 0..TREE_DEPTH {
            let sibling = path.path.get(i).copied().unwrap_or(Fr::from(0u64));
            let is_right = path.indices.get(i).copied().unwrap_or(false);
            cur = if is_right {
                poseidon_hash(&[sibling, cur])
            } else {
                poseidon_hash(&[cur, sibling])
            };
        }
        cur
    } else {
        Fr::from(0u64)
    };

    let asset_id = input_notes.first().map(|n| n.asset_id).unwrap_or(Fr::from(0u64));

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

/// Extract public inputs from a circuit for verification.
///
/// Order and arity MUST match the `new_input` allocations in
/// `TransferCircuit::generate_constraints`:
///   [merkle_root, nullifiers×MAX_INPUTS, output_commitments×MAX_OUTPUTS, asset_id, fee_commitment]
///
/// Slots beyond the actual note count are padded with zero.
pub fn extract_public_inputs(circuit: &TransferCircuit) -> Vec<Fr> {
    use transfer_circuit::{MAX_INPUTS, MAX_OUTPUTS};
    let mut inputs = Vec::new();

    inputs.push(circuit.merkle_root);

    for i in 0..MAX_INPUTS {
        inputs.push(circuit.nullifiers.get(i).copied().unwrap_or(Fr::from(0u64)));
    }

    for i in 0..MAX_OUTPUTS {
        inputs.push(circuit.output_commitments.get(i).copied().unwrap_or(Fr::from(0u64)));
    }

    inputs.push(circuit.asset_id);
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