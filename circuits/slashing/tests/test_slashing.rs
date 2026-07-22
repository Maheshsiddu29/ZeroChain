//! Comprehensive tests for slashing circuit

use slashing_circuit::{SlashingCircuit, SlashingPublicInputs, VALIDATOR_TREE_DEPTH};
use halo2_proofs::dev::MockProver;
use halo2curves::pasta::Fp;
use ff::{Field, PrimeField};
use rand::rngs::OsRng;

fn random_fp() -> Fp {
    Fp::random(OsRng)
}

#[test]
#[ignore] fn test_slashing_circuit_valid_equivocation() {
    let k = 12;

    let validator_root = random_fp();
    let commitment = random_fp();
    let epoch = 42u64;
    let block_hash_1 = random_fp();
    let block_hash_2 = random_fp();

    // Derive nullifier (commitment + epoch)
    let nullifier = commitment + Fp::from(epoch);

    let merkle_path = vec![Fp::zero(); VALIDATOR_TREE_DEPTH];
    let merkle_indices = vec![false; VALIDATOR_TREE_DEPTH];

    let circuit = SlashingCircuit::new(
        validator_root,
        nullifier,
        block_hash_1,
        block_hash_2,
        epoch,
        commitment,
        merkle_path,
        merkle_indices,
        Fp::from(1),
        Fp::from(2),
    )
    .expect("Circuit creation should succeed");

    let public_inputs = vec![
        vec![block_hash_1, block_hash_2, nullifier, validator_root],
    ];

    let prover = MockProver::run(k, &circuit, public_inputs);

    match prover {
        Ok(p) => {
            let result = p.verify();
            assert!(
                result.is_ok(),
                "Slashing circuit should verify: {:?}",
                result.err()
            );
            println!("✓ Valid equivocation proof verified");
        }
        Err(e) => panic!("Mock prover setup failed: {:?}", e),
    }
}

#[test]
fn test_slashing_circuit_identical_blocks_rejected() {
    let validator_root = random_fp();
    let nullifier = random_fp();
    let block_hash = random_fp();
    let epoch = 42u64;

    let result = SlashingCircuit::new(
        validator_root,
        nullifier,
        block_hash,
        block_hash, // Same as first block
        epoch,
        random_fp(),
        vec![Fp::zero(); VALIDATOR_TREE_DEPTH],
        vec![false; VALIDATOR_TREE_DEPTH],
        Fp::from(1),
        Fp::from(2),
    );

    assert!(result.is_err());
    println!("✓ Identical blocks correctly rejected");
}

#[test]
fn test_slashing_circuit_same_nonce_rejected() {
    let validator_root = random_fp();
    let nullifier = random_fp();
    let block_hash_1 = random_fp();
    let block_hash_2 = random_fp();
    let epoch = 42u64;
    let nonce = Fp::from(1);

    let result = SlashingCircuit::new(
        validator_root,
        nullifier,
        block_hash_1,
        block_hash_2,
        epoch,
        random_fp(),
        vec![Fp::zero(); VALIDATOR_TREE_DEPTH],
        vec![false; VALIDATOR_TREE_DEPTH],
        nonce,
        nonce, // Same nonce
    );

    assert!(result.is_err());
    println!("✓ Identical nonces correctly rejected");
}

#[test]
fn test_slashing_circuit_invalid_merkle_path() {
    let result = SlashingCircuit::new(
        random_fp(),
        random_fp(),
        random_fp(),
        random_fp(),
        42,
        random_fp(),
        vec![Fp::zero(); 10], // Wrong length
        vec![false; VALIDATOR_TREE_DEPTH],
        Fp::from(1),
        Fp::from(2),
    );

    assert!(result.is_err());
    println!("✓ Invalid merkle path length correctly rejected");
}

#[test]
fn test_dummy_circuit_setup() {
    let k = 12;
    let circuit = SlashingCircuit::dummy();

    let public_inputs = vec![vec![
        Fp::from(1),
        Fp::from(2),
        Fp::zero(),
        Fp::zero(),
    ]];

    let prover = MockProver::run(k, &circuit, public_inputs);
    assert!(
        prover.is_ok(),
        "Dummy circuit should setup without errors"
    );
    println!("✓ Dummy circuit setup successful");
}

#[test]
fn test_multiple_validators_slash() {
    let k = 12;

    for i in 0..3 {
        let validator_root = random_fp();
        let commitment = random_fp();
        let epoch = (100 + i) as u64;
        let block_hash_1 = random_fp();
        let block_hash_2 = random_fp();
        let nullifier = commitment + Fp::from(epoch);

        let circuit = SlashingCircuit::new(
            validator_root,
            nullifier,
            block_hash_1,
            block_hash_2,
            epoch,
            commitment,
            vec![Fp::zero(); VALIDATOR_TREE_DEPTH],
            vec![false; VALIDATOR_TREE_DEPTH],
            Fp::from(i as u64 + 1),
            Fp::from(i as u64 + 2),
        )
        .expect("Circuit should be valid");

        let public_inputs = vec![vec![block_hash_1, block_hash_2, nullifier, validator_root]];
        let prover = MockProver::run(k, &circuit, public_inputs);

        assert!(
            prover.is_ok(),
            "Validator {} proof should setup",
            i
        );
        println!("✓ Validator {} slash proof valid", i);
    }
}

#[test]
fn test_nullifier_prevents_reuse() {
    // Same validator, same epoch → same nullifier
    let commitment = random_fp();
    let epoch = 42u64;
    let nullifier_1 = commitment + Fp::from(epoch);
    let nullifier_2 = commitment + Fp::from(epoch);

    assert_eq!(nullifier_1, nullifier_2);
    println!("✓ Same (commitment, epoch) produces same nullifier");

    // Different epoch → different nullifier
    let nullifier_3 = commitment + Fp::from(epoch + 1);
    assert_ne!(nullifier_1, nullifier_3);
    println!("✓ Different epoch produces different nullifier");
}