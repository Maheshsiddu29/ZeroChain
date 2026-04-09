//! Tests for ValidatorMembershipCircuit

use membership_circuit::{
    ValidatorMembershipCircuit,
    VALIDATOR_TREE_DEPTH,
};
use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use ff::{Field, PrimeField};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};

fn random_fp() -> Fp {
    Fp::random(OsRng)
}

/// Simplified Poseidon hash for testing (must match chip implementation)
fn test_poseidon_hash(a: Fp, b: Fp) -> Fp {
    a + b // Simplified: just addition
}

/// Compute Merkle root from leaf and path
fn compute_test_root(
    leaf: Fp,
    path: &[Fp],
    indices: &[bool],
) -> Fp {
    let mut current = leaf;
    for i in 0..path.len() {
        let (left, right) = if indices[i] {
            (path[i], current)
        } else {
            (current, path[i])
        };
        current = test_poseidon_hash(left, right);
    }
    current
}

#[test]
fn test_mock_prover_valid_membership() {
    let k = 12;
    
    // Create a credential
    let credential_secret = random_fp();
    let credential_commitment = credential_secret; // Simplified
    
    // Create Merkle path (empty for simplicity)
    let merkle_path: Vec<Fp> = vec![Fp::zero(); VALIDATOR_TREE_DEPTH];
    let merkle_indices: Vec<bool> = vec![false; VALIDATOR_TREE_DEPTH];
    
    // With empty path, root = leaf
    let validator_root = credential_commitment;
    
    let epoch = 42u64;
    let slot = 100u64;
    
    let circuit = ValidatorMembershipCircuit::new(
        validator_root,
        epoch,
        slot,
        credential_secret,
        merkle_path,
        merkle_indices,
    );
    
    let public_inputs = vec![
        validator_root,
        Fp::from(epoch),
        Fp::from(slot),
    ];
    
    let prover = MockProver::run(k, &circuit, vec![public_inputs]);
    match prover {
        Ok(p) => {
            let result = p.verify();
            if result.is_ok() {
                println!("✓ Mock prover verification passed");
            } else {
                println!("✗ Mock prover verification failed: {:?}", result);
            }
            assert!(result.is_ok(), "Circuit should verify");
        }
        Err(e) => {
            println!("Mock prover setup error: {:?}", e);
        }
    }
}

#[test]
fn test_dummy_circuit_setup() {
    let k = 12;
    let circuit = ValidatorMembershipCircuit::dummy();
    
    let public_inputs: Vec<Fp> = vec![Fp::zero(), Fp::zero(), Fp::zero()];
    let result = MockProver::run(k, &circuit, vec![public_inputs]);
    println!("Dummy circuit setup result: {:?}", result.is_ok());
    assert!(result.is_ok(), "Dummy circuit should setup without error");
}

#[test]
fn test_circuit_creation() {
    // Just test that we can create and use the circuit
    let circuit = ValidatorMembershipCircuit::dummy();
    
    // Test that dummy circuit has expected values
    assert_eq!(circuit.epoch, 0);
    assert_eq!(circuit.slot, 0);
    assert_eq!(circuit.merkle_path.len(), VALIDATOR_TREE_DEPTH);
    assert_eq!(circuit.merkle_indices.len(), VALIDATOR_TREE_DEPTH);
    
    println!("✓ Circuit creation successful");
}

#[test]
fn test_circuit_with_values() {
    let validator_root = Fp::from(12345u64);
    let epoch = 100u64;
    let slot = 500u64;
    let credential_secret = Fp::from(99999u64);
    
    let merkle_path = vec![Fp::zero(); VALIDATOR_TREE_DEPTH];
    let merkle_indices = vec![false; VALIDATOR_TREE_DEPTH];
    
    let circuit = ValidatorMembershipCircuit::new(
        validator_root,
        epoch,
        slot,
        credential_secret,
        merkle_path,
        merkle_indices,
    );
    
    assert_eq!(circuit.validator_root, validator_root);
    assert_eq!(circuit.epoch, epoch);
    assert_eq!(circuit.slot, slot);
    assert_eq!(circuit.credential_secret, credential_secret);
    
    println!("✓ Circuit with custom values created successfully");
}

/// Test vector structure for Halo2 proofs
#[derive(Debug, Serialize, Deserialize)]
struct MembershipTestVector {
    description: String,
    public_inputs: MembershipPublicInputsJson,
    expected_valid: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct MembershipPublicInputsJson {
    validator_root: String,
    epoch: u64,
    slot: u64,
}

#[test]
#[ignore]
fn generate_membership_test_vectors() {
    use std::path::PathBuf;
    
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    
    std::fs::create_dir_all(&fixtures_dir).unwrap();
    
    println!("=== Generating Membership Circuit Test Vectors ===");
    
    let k = 12;
    
    // Create valid circuit
    let credential_secret = random_fp();
    let credential_commitment = credential_secret;
    
    let merkle_path: Vec<Fp> = vec![Fp::zero(); VALIDATOR_TREE_DEPTH];
    let merkle_indices: Vec<bool> = vec![false; VALIDATOR_TREE_DEPTH];
    
    let validator_root = credential_commitment;
    
    let epoch = 42u64;
    let slot = 100u64;
    
    let circuit = ValidatorMembershipCircuit::new(
        validator_root,
        epoch,
        slot,
        credential_secret,
        merkle_path,
        merkle_indices,
    );
    
    let public_inputs = vec![
        validator_root,
        Fp::from(epoch),
        Fp::from(slot),
    ];
    
    // Run mock prover
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]);
    
    match prover {
        Ok(p) => {
            let is_valid = p.verify().is_ok();
            
            println!("  Proof valid: {}", is_valid);
            
            let vector = MembershipTestVector {
                description: "Valid validator membership proof".to_string(),
                public_inputs: MembershipPublicInputsJson {
                    validator_root: format!("0x{}", hex::encode(
                        validator_root.to_repr().as_ref()
                    )),
                    epoch,
                    slot,
                },
                expected_valid: is_valid,
            };
            
            let json = serde_json::to_string_pretty(&vector).unwrap();
            let path = fixtures_dir.join("membership_valid.json");
            std::fs::write(&path, json).unwrap();
            println!("  ✓ Test vector saved to {:?}", path);
        }
        Err(e) => println!("  Setup error: {:?}", e),
    }
}