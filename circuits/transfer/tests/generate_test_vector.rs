//! Test vector generation for TransferCircuit
//! 
//! Run: cargo test -p circuits-transfer --test generate_vectors -- --ignored --nocapture

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

// Import from the circuits crate
use circuits_transfer::{TransferCircuit, InputNote, OutputNote, TransferWitness};

/// JSON structure for test vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVectorJson {
    pub description: String,
    pub witness: WitnessJson,
    pub public_inputs: PublicInputsJson,
    pub proof: ProofJson,
    pub verifying_key: String,
    pub expected_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessJson {
    pub input_notes: Vec<InputNoteJson>,
    pub output_notes: Vec<OutputNoteJson>,
    pub fee: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputNoteJson {
    pub value: String,
    pub asset_id: String,
    pub blinding: String,
    pub nullifier_key: String,
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
    
    // Step 2: Generate valid 2-in-2-out vector
    println!("Step 2: Generating valid 2-in-2-out test vector...");
    let vector_2in2out = generate_valid_2in_2out(&pk, &vk);
    save_test_vector(&vector_2in2out, &fixtures_dir.join("transfer_valid_2in_2out.json"));
    println!("  Vector saved\n");
    
    // Step 3: Generate valid 1-in-1-out vector
    println!("Step 3: Generating valid 1-in-1-out test vector...");
    let vector_1in1out = generate_valid_1in_1out(&pk, &vk);
    save_test_vector(&vector_1in1out, &fixtures_dir.join("transfer_valid_1in_1out.json"));
    println!("  Vector saved\n");
    
    // Step 4: Generate Poseidon test vectors for Akshay
    println!("Step 4: Generating Poseidon hash test vectors...");
    generate_poseidon_vectors(&fixtures_dir);
    println!("  Poseidon vectors saved\n");
    
    println!("=== All test vectors generated successfully! ===");
}

fn generate_circuit_keys() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    // Create dummy circuit for setup
    let dummy_witness = create_dummy_witness(2, 2);
    let dummy_circuit = TransferCircuit::new(dummy_witness);
    
    let mut rng = OsRng;
    Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, &mut rng)
        .expect("Circuit setup failed")
}

fn generate_valid_2in_2out(pk: &ProvingKey<Bn254>, vk: &VerifyingKey<Bn254>) -> TestVectorJson {
    let mut rng = OsRng;
    
    // Create two input notes
    let input_note_1 = InputNote {
        value: 500_000_000_000_000u64, // 500 ZERO
        asset_id: [0u8; 32],
        blinding: Fr::rand(&mut rng),
        nullifier_key: Fr::rand(&mut rng),
        merkle_path: generate_random_merkle_path(&mut rng),
        merkle_indices: generate_random_indices(),
    };
    
    let input_note_2 = InputNote {
        value: 500_000_000_000_000u64,
        asset_id: [0u8; 32],
        blinding: Fr::rand(&mut rng),
        nullifier_key: Fr::rand(&mut rng),
        merkle_path: generate_random_merkle_path(&mut rng),
        merkle_indices: generate_random_indices(),
    };
    
    // Create two output notes (total = 1000 - 10 fee = 990)
    let output_note_1 = OutputNote {
        value: 400_000_000_000_000u64,
        asset_id: [0u8; 32],
        recipient_pubkey: Fr::rand(&mut rng),
        blinding: Fr::rand(&mut rng),
    };
    
    let output_note_2 = OutputNote {
        value: 590_000_000_000_000u64,
        asset_id: [0u8; 32],
        recipient_pubkey: Fr::rand(&mut rng),
        blinding: Fr::rand(&mut rng),
    };
    
    let fee = 10_000_000_000_000u64; // 10 ZERO
    let fee_blinding = Fr::rand(&mut rng);
    
    let witness = TransferWitness {
        input_notes: vec![input_note_1.clone(), input_note_2.clone()],
        output_notes: vec![output_note_1.clone(), output_note_2.clone()],
        fee,
        fee_blinding,
    };
    
    // Build circuit and generate proof
    let circuit = TransferCircuit::new(witness.clone());
    
    // Calculate public inputs
    let merkle_root = compute_merkle_root(&input_note_1);
    let nullifier_1 = compute_nullifier(&input_note_1);
    let nullifier_2 = compute_nullifier(&input_note_2);
    let commitment_1 = compute_output_commitment(&output_note_1);
    let commitment_2 = compute_output_commitment(&output_note_2);
    let fee_commitment = compute_fee_commitment(fee, fee_blinding);
    
    // Generate proof
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .expect("Proof generation failed");
    
    // Verify proof
    let public_inputs = vec![
        merkle_root,
        nullifier_1,
        nullifier_2,
        commitment_1,
        commitment_2,
        Fr::from(0u64), // asset_id as field element
        fee_commitment,
    ];
    
    let pvk = PreparedVerifyingKey::from(vk.clone());
    let is_valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        .expect("Verification failed");
    
    assert!(is_valid, "Generated proof must be valid!");
    println!("  Proof verified locally");
    
    // Convert to JSON format
    TestVectorJson {
        description: "Valid 2-input 2-output shielded transfer".to_string(),
        witness: WitnessJson {
            input_notes: vec![
                input_note_to_json(&input_note_1),
                input_note_to_json(&input_note_2),
            ],
            output_notes: vec![
                output_note_to_json(&output_note_1),
                output_note_to_json(&output_note_2),
            ],
            fee: fee.to_string(),
        },
        public_inputs: PublicInputsJson {
            merkle_root: fr_to_hex(&merkle_root),
            nullifiers: vec![fr_to_hex(&nullifier_1), fr_to_hex(&nullifier_2)],
            output_commitments: vec![fr_to_hex(&commitment_1), fr_to_hex(&commitment_2)],
            asset_id: bytes_to_hex(&[0u8; 32]),
            fee_commitment: fr_to_hex(&fee_commitment),
        },
        proof: proof_to_json(&proof),
        verifying_key: vk_to_hex(vk),
        expected_valid: true,
    }
}

fn generate_valid_1in_1out(pk: &ProvingKey<Bn254>, vk: &VerifyingKey<Bn254>) -> TestVectorJson {
    let mut rng = OsRng;
    
    let input_note = InputNote {
        value: 100_000_000_000_000u64,
        asset_id: [0u8; 32],
        blinding: Fr::rand(&mut rng),
        nullifier_key: Fr::rand(&mut rng),
        merkle_path: generate_random_merkle_path(&mut rng),
        merkle_indices: generate_random_indices(),
    };
    
    let output_note = OutputNote {
        value: 99_000_000_000_000u64,
        asset_id: [0u8; 32],
        recipient_pubkey: Fr::rand(&mut rng),
        blinding: Fr::rand(&mut rng),
    };
    
    let fee = 1_000_000_000_000u64;
    let fee_blinding = Fr::rand(&mut rng);
    
    let witness = TransferWitness {
        input_notes: vec![input_note.clone()],
        output_notes: vec![output_note.clone()],
        fee,
        fee_blinding,
    };
    
    let circuit = TransferCircuit::new(witness);
    
    let merkle_root = compute_merkle_root(&input_note);
    let nullifier = compute_nullifier(&input_note);
    let commitment = compute_output_commitment(&output_note);
    let fee_commitment = compute_fee_commitment(fee, fee_blinding);
    
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .expect("Proof generation failed");
    
    let public_inputs = vec![
        merkle_root,
        nullifier,
        commitment,
        Fr::from(0u64),
        fee_commitment,
    ];
    
    let pvk = PreparedVerifyingKey::from(vk.clone());
    let is_valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
        .expect("Verification failed");
    
    assert!(is_valid);
    println!("  Proof verified locally");
    
    TestVectorJson {
        description: "Valid 1-input 1-output shielded transfer".to_string(),
        witness: WitnessJson {
            input_notes: vec![input_note_to_json(&input_note)],
            output_notes: vec![output_note_to_json(&output_note)],
            fee: fee.to_string(),
        },
        public_inputs: PublicInputsJson {
            merkle_root: fr_to_hex(&merkle_root),
            nullifiers: vec![fr_to_hex(&nullifier)],
            output_commitments: vec![fr_to_hex(&commitment)],
            asset_id: bytes_to_hex(&[0u8; 32]),
            fee_commitment: fr_to_hex(&fee_commitment),
        },
        proof: proof_to_json(&proof),
        verifying_key: vk_to_hex(vk),
        expected_valid: true,
    }
}

/// Generate Poseidon test vectors for Akshay's parity testing
fn generate_poseidon_vectors(fixtures_dir: &PathBuf) {
    use circuits_transfer::poseidon::PoseidonHasher;
    
    #[derive(Serialize)]
    struct PoseidonVector {
        inputs: Vec<String>,
        output: String,
    }
    
    #[derive(Serialize)]
    struct PoseidonVectors {
        description: String,
        field: String,
        vectors: Vec<PoseidonVector>,
    }
    
    let mut rng = OsRng;
    let mut vectors = Vec::new();
    
    // Generate 20 test vectors
    for i in 0..20 {
        let num_inputs = (i % 4) + 1; // 1 to 4 inputs
        let inputs: Vec<Fr> = (0..num_inputs).map(|_| Fr::rand(&mut rng)).collect();
        let output = PoseidonHasher::hash(&inputs);
        
        vectors.push(PoseidonVector {
            inputs: inputs.iter().map(fr_to_hex).collect(),
            output: fr_to_hex(&output),
        });
    }
    
    // Add specific known test vectors
    // Vector with small inputs
    let small_inputs = vec![Fr::from(1u64), Fr::from(2u64)];
    let small_output = PoseidonHasher::hash(&small_inputs);
    vectors.push(PoseidonVector {
        inputs: small_inputs.iter().map(fr_to_hex).collect(),
        output: fr_to_hex(&small_output),
    });
    
    // Vector with zeros
    let zero_inputs = vec![Fr::from(0u64), Fr::from(0u64)];
    let zero_output = PoseidonHasher::hash(&zero_inputs);
    vectors.push(PoseidonVector {
        inputs: zero_inputs.iter().map(fr_to_hex).collect(),
        output: fr_to_hex(&zero_output),
    });
    
    let poseidon_vectors = PoseidonVectors {
        description: "Poseidon hash test vectors for BN254 Fr field".to_string(),
        field: "BN254_Fr".to_string(),
        vectors,
    };
    
    let json = serde_json::to_string_pretty(&poseidon_vectors)
        .expect("JSON serialization failed");
    
    let path = fixtures_dir.join("poseidon_vectors.json");
    fs::write(&path, json).expect("Failed to write Poseidon vectors");
    println!("  Poseidon vectors saved to {:?}", path);
}

// Helper functions

fn create_dummy_witness(num_inputs: usize, num_outputs: usize) -> TransferWitness {
    let mut rng = OsRng;
    
    let input_notes: Vec<InputNote> = (0..num_inputs)
        .map(|_| InputNote {
            value: 100u64,
            asset_id: [0u8; 32],
            blinding: Fr::rand(&mut rng),
            nullifier_key: Fr::rand(&mut rng),
            merkle_path: generate_random_merkle_path(&mut rng),
            merkle_indices: generate_random_indices(),
        })
        .collect();
    
    let output_notes: Vec<OutputNote> = (0..num_outputs)
        .map(|_| OutputNote {
            value: 90u64,
            asset_id: [0u8; 32],
            recipient_pubkey: Fr::rand(&mut rng),
            blinding: Fr::rand(&mut rng),
        })
        .collect();
    
    TransferWitness {
        input_notes,
        output_notes,
        fee: 10u64 * num_inputs as u64,
        fee_blinding: Fr::rand(&mut rng),
    }
}

fn generate_random_merkle_path(rng: &mut OsRng) -> Vec<Fr> {
    (0..32).map(|_| Fr::rand(rng)).collect()
}

fn generate_random_indices() -> Vec<bool> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32).map(|_| rng.gen()).collect()
}

fn compute_merkle_root(note: &InputNote) -> Fr {
    use circuits_transfer::poseidon::PoseidonHasher;
    
    let leaf = compute_note_commitment(note);
    let mut current = leaf;
    
    for (i, sibling) in note.merkle_path.iter().enumerate() {
        let is_right = note.merkle_indices[i];
        current = if is_right {
            PoseidonHasher::hash_two(*sibling, current)
        } else {
            PoseidonHasher::hash_two(current, *sibling)
        };
    }
    current
}

fn compute_note_commitment(note: &InputNote) -> Fr {
    use circuits_transfer::poseidon::PoseidonHasher;
    
    PoseidonHasher::hash(&[
        Fr::from(note.value),
        Fr::from_le_bytes_mod_order(&note.asset_id),
        note.blinding,
        note.nullifier_key,
    ])
}

fn compute_nullifier(note: &InputNote) -> Fr {
    use circuits_transfer::poseidon::PoseidonHasher;
    let commitment = compute_note_commitment(note);
    PoseidonHasher::hash_two(note.nullifier_key, commitment)
}

fn compute_output_commitment(note: &OutputNote) -> Fr {
    use circuits_transfer::poseidon::PoseidonHasher;
    
    PoseidonHasher::hash(&[
        Fr::from(note.value),
        Fr::from_le_bytes_mod_order(&note.asset_id),
        note.recipient_pubkey,
        note.blinding,
    ])
}

fn compute_fee_commitment(fee: u64, blinding: Fr) -> Fr {
    use circuits_transfer::poseidon::PoseidonHasher;
    PoseidonHasher::hash_two(Fr::from(fee), blinding)
}

fn fr_to_hex(fr: &Fr) -> String {
    let mut bytes = Vec::new();
    fr.serialize_uncompressed(&mut bytes).unwrap();
    format!("0x{}", hex::encode(&bytes))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn input_note_to_json(note: &InputNote) -> InputNoteJson {
    InputNoteJson {
        value: note.value.to_string(),
        asset_id: bytes_to_hex(&note.asset_id),
        blinding: fr_to_hex(&note.blinding),
        nullifier_key: fr_to_hex(&note.nullifier_key),
        merkle_path: note.merkle_path.iter().map(fr_to_hex).collect(),
        merkle_indices: note.merkle_indices.iter().map(|&b| if b { 1 } else { 0 }).collect(),
    }
}

fn output_note_to_json(note: &OutputNote) -> OutputNoteJson {
    OutputNoteJson {
        value: note.value.to_string(),
        asset_id: bytes_to_hex(&note.asset_id),
        recipient_pubkey: fr_to_hex(&note.recipient_pubkey),
        blinding: fr_to_hex(&note.blinding),
    }
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

fn vk_to_hex(vk: &VerifyingKey<Bn254>) -> String {
    let mut bytes = Vec::new();
    vk.serialize_uncompressed(&mut bytes).unwrap();
    format!("0x{}", hex::encode(&bytes))
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