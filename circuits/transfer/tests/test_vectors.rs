//! Generate test vectors for Mahesh to verify on-chain

use transfer_circuit::*;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::rand::thread_rng;
use std::fs::File;
use std::io::Write;

#[test]
fn generate_test_vectors() {
    let mut rng = thread_rng();
    
    // 1. Create circuit
    let circuit = TransferCircuit::test_circuit();
    
    // 2. Generate proving/verifying keys (trusted setup)
    println!("Running trusted setup...");
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
    
    // 3. Generate proof
    println!("Generating proof...");
    let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
    
    // 4. Extract public inputs
    let public_inputs = vec![
        circuit.merkle_root,
        circuit.nullifiers[0],
        circuit.output_commitments[0],
        circuit.asset_id,
        circuit.fee_commitment,
    ];
    
    // 5. Verify proof (sanity check)
    let valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();
    assert!(valid, "Proof verification failed!");
    
    // 6. Serialize to bytes (matching primitives/zk-types format)
    let mut proof_bytes = Vec::new();
    proof.serialize_uncompressed(&mut proof_bytes).unwrap();
    
    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes).unwrap();
    
    // 7. Save test vector
    let test_vector = serde_json::json!({
        "proof": hex::encode(&proof_bytes),
        "public_inputs": {
            "merkle_root": format!("{:?}", circuit.merkle_root),
            "nullifiers": vec![format!("{:?}", circuit.nullifiers[0])],
            "output_commitments": vec![format!("{:?}", circuit.output_commitments[0])],
            "asset_id": format!("{:?}", circuit.asset_id),
            "fee_commitment": format!("{:?}", circuit.fee_commitment),
        },
        "verification_result": valid,
    });
    
    let mut file = File::create("tests/fixtures/test_vector_001.json").unwrap();
    file.write_all(test_vector.to_string().as_bytes()).unwrap();
    
    // 8. Save verifying key
    let mut vk_file = File::create("../../keys/transfer.vk").unwrap();
    vk_file.write_all(&vk_bytes).unwrap();
    
    println!(" Test vector generated!");
    println!("   Proof size: {} bytes", proof_bytes.len());
    println!("   VK size: {} bytes", vk_bytes.len());
    println!("   Saved to: tests/fixtures/test_vector_001.json");
}