//! Test vector generation for TransferCircuit
//!
//! Run: cargo test -p transfer-circuit --test generate_test_vector -- --ignored --nocapture

use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_serialize::CanonicalSerialize;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use transfer_circuit::{TransferCircuit, Note, MerklePath};

/// JSON structure for test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVectorJson {
    pub description: String,
    pub witness: WitnessJson,
    pub public_inputs: PublicInputsJson,
    pub proof: ProofJson,
    pub expected_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessJson {
    pub input_notes: Vec<InputNoteJson>,
    pub output_notes: Vec<OutputNoteJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputNoteJson {
    pub value: String,
    pub asset_id: String,
    pub blinding: String,
    pub nullifier_key: String,
    pub owner_pubkey: String,
    pub merkle_path: Vec<String>,
    pub merkle_indices: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputNoteJson {
    pub value: String,
    pub asset_id: String,
    pub recipient_pubkey: String,
    pub blinding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputsJson {
    pub merkle_root: String,
    pub nullifiers: Vec<String>,
    pub output_commitments: Vec<String>,
    pub asset_id: String,
    pub fee_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofJson {
    pub a: String,
    pub b: String,
    pub c: String,
}

/// Generate all test vectors
#[test]
#[ignore]
fn generate_all_test_vectors() {
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");

    fs::create_dir_all(&fixtures_dir).expect("Failed to create fixtures directory");

    println!("=== Generating Transfer Circuit Test Vectors ===\n");

    // Step 1: Generate keys
    println!("Step 1: Generating proving and verifying keys...");
    let (pk, vk) = generate_circuit_keys();
    println!("  Keys generated\n");

    // Save verifying key
    let vk_path = fixtures_dir.join("transfer_verifying_key.bin");
    save_verifying_key(&vk, &vk_path);
    println!("  Verifying key saved to {:?}\n", vk_path);

    // Step 2: Generate valid 1-in-1-out vector
    println!("Step 2: Generating valid 1-in-1-out test vector...");
    let vector_1in1out = generate_valid_1in_1out(&pk, &vk);
    save_test_vector(&vector_1in1out, &fixtures_dir.join("transfer_valid_1in_1out.json"));
    println!("  Vector saved\n");

    // Step 3: Generate Poseidon test vectors
    println!("Step 3: Generating Poseidon hash test vectors...");
    generate_poseidon_vectors(&fixtures_dir);
    println!("  Poseidon vectors saved\n");

    println!("=== All test vectors generated successfully! ===");
}

fn generate_circuit_keys() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    // Create dummy circuit for setup (1-in-1-out)
    let mut rng = StdRng::seed_from_u64(0);

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

    let dummy_circuit = TransferCircuit {
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

    let mut rng = StdRng::seed_from_u64(1);
    Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, &mut rng)
        .expect("Circuit setup failed")
}

fn generate_valid_1in_1out(pk: &ProvingKey<Bn254>, vk: &VerifyingKey<Bn254>) -> TestVectorJson {
    let mut rng = StdRng::seed_from_u64(42);

    let secret_key = Fr::rand(&mut rng);
    let asset_id = Fr::from(0u64);

    let input_note = Note {
        value: 100_000_000_000_000u64, // 100 ZERO
        asset_id,
        blinding: Fr::rand(&mut rng),
        owner_pubkey: Fr::rand(&mut rng),
    };

    let output_note = Note {
        value: 100_000_000_000_000u64,
        asset_id,
        blinding: Fr::rand(&mut rng),
        owner_pubkey: Fr::rand(&mut rng),
    };

    // Compute circuit values (simplified: addition)
    let input_value_fr = Fr::from(input_note.value);
    let input_commitment = input_value_fr + input_note.asset_id + input_note.blinding + input_note.owner_pubkey;
    let nullifier = input_commitment + secret_key;

    let output_value_fr = Fr::from(output_note.value);
    let output_commitment = output_value_fr + output_note.asset_id + output_note.blinding + output_note.owner_pubkey;

    let merkle_path = MerklePath { path: vec![], indices: vec![] };

    let circuit = TransferCircuit {
        input_notes: vec![input_note.clone()],
        output_notes: vec![output_note.clone()],
        merkle_paths: vec![merkle_path.clone()],
        secret_keys: vec![secret_key],
        merkle_root: input_commitment, // With empty path, root = commitment
        nullifiers: vec![nullifier],
        output_commitments: vec![output_commitment],
        asset_id,
        fee_commitment: Fr::from(0u64),
    };

    let public_inputs = vec![
        input_commitment, // merkle_root
        nullifier,
        output_commitment,
        asset_id,
        Fr::from(0u64), // fee_commitment
    ];

    // Generate proof
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .expect("Proof generation failed");

    // Verify proof
    let pvk = Groth16::<Bn254>::process_vk(vk)
        .expect("VK processing failed");
    let is_valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        .expect("Verification failed");

    assert!(is_valid, "Generated proof must be valid!");
    println!("  Proof verified locally");

    // Convert to JSON format
    TestVectorJson {
        description: "Valid 1-input 1-output shielded transfer (simplified hash)".to_string(),
        witness: WitnessJson {
            input_notes: vec![InputNoteJson {
                value: input_note.value.to_string(),
                asset_id: bytes_to_hex(&fr_to_bytes(&input_note.asset_id)),
                blinding: fr_to_hex(&input_note.blinding),
                nullifier_key: fr_to_hex(&secret_key),
                owner_pubkey: fr_to_hex(&input_note.owner_pubkey),
                merkle_path: vec![],
                merkle_indices: vec![],
            }],
            output_notes: vec![OutputNoteJson {
                value: output_note.value.to_string(),
                asset_id: bytes_to_hex(&fr_to_bytes(&output_note.asset_id)),
                recipient_pubkey: fr_to_hex(&output_note.owner_pubkey),
                blinding: fr_to_hex(&output_note.blinding),
            }],
        },
        public_inputs: PublicInputsJson {
            merkle_root: fr_to_hex(&input_commitment),
            nullifiers: vec![fr_to_hex(&nullifier)],
            output_commitments: vec![fr_to_hex(&output_commitment)],
            asset_id: bytes_to_hex(&[0u8; 32]),
            fee_commitment: fr_to_hex(&Fr::from(0u64)),
        },
        proof: proof_to_json(&proof),
        expected_valid: true,
    }
}

/// Generate Poseidon test vectors
fn generate_poseidon_vectors(fixtures_dir: &PathBuf) {
    #[derive(Serialize)]
    struct PoseidonVector {
        inputs: Vec<String>,
        output: String,
    }

    #[derive(Serialize)]
    struct PoseidonVectors {
        description: String,
        field: String,
        hash_function: String,
        vectors: Vec<PoseidonVector>,
    }

    let mut rng = StdRng::seed_from_u64(12345);
    let mut vectors = Vec::new();

    // Generate 10 test vectors using simplified hash (addition)
    for i in 0..10 {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let output = a + b; // Simplified hash

        vectors.push(PoseidonVector {
            inputs: vec![fr_to_hex(&a), fr_to_hex(&b)],
            output: fr_to_hex(&output),
        });

        if i == 0 {
            println!("  Sample: {} + {} = {}", fr_to_hex(&a), fr_to_hex(&b), fr_to_hex(&output));
        }
    }

    // Add specific known test vectors
    let zero_zero = Fr::from(0u64) + Fr::from(0u64);
    vectors.push(PoseidonVector {
        inputs: vec![fr_to_hex(&Fr::from(0u64)), fr_to_hex(&Fr::from(0u64))],
        output: fr_to_hex(&zero_zero),
    });

    let one_two = Fr::from(1u64) + Fr::from(2u64);
    vectors.push(PoseidonVector {
        inputs: vec![fr_to_hex(&Fr::from(1u64)), fr_to_hex(&Fr::from(2u64))],
        output: fr_to_hex(&one_two),
    });

    let poseidon_vectors = PoseidonVectors {
        description: "Simplified hash test vectors (addition) for BN254 Fr field".to_string(),
        field: "BN254_Fr".to_string(),
        hash_function: "simplified_addition (a + b)".to_string(),
        vectors,
    };

    let json = serde_json::to_string_pretty(&poseidon_vectors)
        .expect("JSON serialization failed");

    let path = fixtures_dir.join("poseidon_vectors.json");
    fs::write(&path, json).expect("Failed to write Poseidon vectors");
    println!("  Poseidon vectors saved to {:?}", path);
}

// Helper functions

fn fr_to_hex(fr: &Fr) -> String {
    let bytes = fr_to_bytes(fr);
    format!("0x{}", hex::encode(&bytes))
}

fn fr_to_bytes(fr: &Fr) -> Vec<u8> {
    let mut bytes = Vec::new();
    fr.serialize_uncompressed(&mut bytes).unwrap();
    bytes
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn proof_to_json(proof: &Proof<Bn254>) -> ProofJson {
    let mut a_bytes = Vec::new();
    let mut b_bytes = Vec::new();
    let mut c_bytes = Vec::new();

    proof.a.serialize_uncompressed(&mut a_bytes).unwrap();
    proof.b.serialize_uncompressed(&mut b_bytes).unwrap();
    proof.c.serialize_uncompressed(&mut c_bytes).unwrap();

    ProofJson {
        a: format!("0x{}", hex::encode(&a_bytes)),
        b: format!("0x{}", hex::encode(&b_bytes)),
        c: format!("0x{}", hex::encode(&c_bytes)),
    }
}

fn save_verifying_key(vk: &VerifyingKey<Bn254>, path: &PathBuf) {
    let mut bytes = Vec::new();
    vk.serialize_uncompressed(&mut bytes).unwrap();
    fs::write(path, &bytes).unwrap();
}

fn save_test_vector(vector: &TestVectorJson, path: &PathBuf) {
    let json = serde_json::to_string_pretty(vector).unwrap();
    fs::write(path, json).unwrap();
    println!("  Saved to {:?}", path);
}