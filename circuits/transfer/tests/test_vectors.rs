//! Generate test vectors for Mahesh to verify on-chain
use transfer_circuit::*;
use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use std::fs::File;
use std::io::Write;

#[test]
fn generate_test_vectors() {
    let mut rng = test_rng();
    
    // 1. Create circuit
    let circuit = TransferCircuit::test_circuit();
    
    // 2. Generate proving key (trusted setup)
    println!("Running trusted setup...");
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
        circuit.clone(), 
        &mut rng
    ).unwrap();
    
    // Extract and prepare verifying key
    let vk = pk.vk.clone();
    let prepared_vk = ark_groth16::prepare_verifying_key(&vk);
    
    // 3. Generate proof
    println!("Generating proof...");
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
        circuit.clone(), 
        &pk, 
        &mut rng
    ).unwrap();
    
    // 4. Extract public inputs
    let public_inputs = vec![
        circuit.merkle_root,
        circuit.nullifiers[0],
        circuit.output_commitments[0],
        circuit.asset_id,
        circuit.fee_commitment,
    ];
    
    // 5. Verify proof (use prepared VK for verification)
    let valid = Groth16::<Bn254>::verify_proof(
        &prepared_vk,  // ← Use prepared VK
        &proof, 
        &public_inputs
    ).unwrap();
    assert!(valid, "Proof verification failed!");
    
    // 6. Serialize to bytes (use regular VK for serialization)
    let mut proof_bytes: Vec<u8> = Vec::new();
    proof.serialize_uncompressed(&mut proof_bytes).unwrap();
    
    let mut vk_bytes: Vec<u8> = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes).unwrap();  // ← Use regular vk
    
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
    
    println!("   Test vector generated!");
    println!("   Proof size: {} bytes", proof_bytes.len());
    println!("   VK size: {} bytes", vk_bytes.len());
    println!("   Saved to: tests/fixtures/test_vector_001.json");
}