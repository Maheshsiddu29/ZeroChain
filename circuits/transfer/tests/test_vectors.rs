//! Test vector validation
//!
//! This test loads and validates the generated test vectors

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_snark::SNARK;
use ark_serialize::CanonicalDeserialize;
use ark_relations::r1cs::ConstraintSynthesizer;
use std::path::PathBuf;

use transfer_circuit::TransferCircuit;

#[test]
fn test_circuit_basic() {
    use ark_relations::r1cs::ConstraintSystem;
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use transfer_circuit::{Note, MerklePath};

    let mut rng = StdRng::seed_from_u64(0);
    let cs = ConstraintSystem::<Fr>::new_ref();

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

    let input_value_fr = Fr::from(input_note.value);
    let input_commitment = input_value_fr + input_note.asset_id + input_note.blinding + input_note.owner_pubkey;
    let nullifier = input_commitment + secret_key;

    let output_value_fr = Fr::from(output_note.value);
    let output_commitment = output_value_fr + output_note.asset_id + output_note.blinding + output_note.owner_pubkey;

    let circuit = TransferCircuit {
        input_notes: vec![input_note],
        output_notes: vec![output_note],
        merkle_paths: vec![MerklePath { path: vec![], indices: vec![] }],
        secret_keys: vec![secret_key],
        merkle_root: input_commitment,
        nullifiers: vec![nullifier],
        output_commitments: vec![output_commitment],
        asset_id,
        fee_commitment: Fr::from(0u64),
    };

    circuit.generate_constraints(cs.clone()).unwrap();

    println!("Circuit constraints: {}", cs.num_constraints());
    assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");
}

#[test]
#[ignore] // Only run if test vectors exist
fn test_load_and_verify_test_vectors() {
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");

    let vector_path = fixtures_dir.join("transfer_valid_1in_1out.json");
    let vk_path = fixtures_dir.join("transfer_verifying_key.bin");

    if !vector_path.exists() || !vk_path.exists() {
        println!("Test vectors not found. Generate them with:");
        println!("cargo test -p transfer-circuit --test generate_test_vector -- --ignored");
        return;
    }

    // Load verifying key
    let vk_bytes = std::fs::read(&vk_path).expect("Failed to read VK");
    let vk = VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(&vk_bytes[..])
        .expect("Failed to deserialize VK");

    // Load test vector
    let vector_json = std::fs::read_to_string(&vector_path)
        .expect("Failed to read test vector");
    let vector: serde_json::Value = serde_json::from_str(&vector_json)
        .expect("Failed to parse test vector JSON");

    // Parse proof
    let proof_a = hex_to_bytes(vector["proof"]["a"].as_str().unwrap());
    let proof_b = hex_to_bytes(vector["proof"]["b"].as_str().unwrap());
    let proof_c = hex_to_bytes(vector["proof"]["c"].as_str().unwrap());

    let a = ark_bn254::G1Affine::deserialize_uncompressed_unchecked(&proof_a[..])
        .expect("Failed to deserialize proof.a");
    let b = ark_bn254::G2Affine::deserialize_uncompressed_unchecked(&proof_b[..])
        .expect("Failed to deserialize proof.b");
    let c = ark_bn254::G1Affine::deserialize_uncompressed_unchecked(&proof_c[..])
        .expect("Failed to deserialize proof.c");

    let proof = Proof { a, b, c };

    // Parse public inputs
    let merkle_root = hex_to_fr(vector["public_inputs"]["merkle_root"].as_str().unwrap());
    let nullifier = hex_to_fr(vector["public_inputs"]["nullifiers"][0].as_str().unwrap());
    let output_commitment = hex_to_fr(vector["public_inputs"]["output_commitments"][0].as_str().unwrap());
    let asset_id = Fr::from(0u64);
    let fee_commitment = Fr::from(0u64);

    let public_inputs = vec![
        merkle_root,
        nullifier,
        output_commitment,
        asset_id,
        fee_commitment,
    ];

    // Verify proof
    let pvk = Groth16::<Bn254>::process_vk(&vk)
        .expect("Failed to process VK");
    let is_valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        .expect("Verification failed");

    assert!(is_valid, "Test vector proof should be valid");
    println!("✓ Test vector proof verified successfully");
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim_start_matches("0x");
    hex::decode(hex).expect("Invalid hex")
}

fn hex_to_fr(hex: &str) -> Fr {
    let bytes = hex_to_bytes(hex);
    Fr::deserialize_uncompressed_unchecked(&bytes[..])
        .expect("Failed to deserialize Fr")
}