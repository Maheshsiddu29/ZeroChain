use crate::{mock::*, Error, Event};
use frame_support::{assert_noop, assert_ok};
use zk_types::*;

fn make_transfer() -> ProofSubmission {
    ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
        proof: Groth16Proof {
            a: [1u8; G1_UNCOMPRESSED_SIZE],
            b: [2u8; G2_UNCOMPRESSED_SIZE],
            c: [3u8; G1_UNCOMPRESSED_SIZE],
        },
        inputs: TransferPublicInputs {
            merkle_root: [0xAA; 32],
            nullifiers: vec![[0xBB; 32], [0xCC; 32]],
            output_commitments: vec![[0xDD; 32], [0xEE; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        },
    }))
}

fn make_membership() -> ProofSubmission {
    ProofSubmission::ValidatorMembership {
        proof: Halo2Proof { proof_bytes: vec![1, 2, 3, 4, 5] },
        inputs: MembershipPublicInputs {
            validator_root: [0x11; 32],
            epoch: 1,
            slot: 10,
        },
    }
}

fn make_lineage() -> ProofSubmission {
    ProofSubmission::StateLineage {
        proof: NovaProof { accumulator: vec![10, 20, 30], block_height: 5 },
        inputs: OriginPublicInputs {
            prev_state_root: [0x22; 32],
            new_state_root: [0x33; 32],
            block_height: 5,
            genesis_hash: [0x00; 32],
            num_steps: 1,
        },
    }
}

/// Helper to decode a hex string (with or without 0x prefix) into bytes
fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    let clean = hex_str.trim_start_matches("0x");
    hex::decode(clean).expect("Invalid hex string")
}

/// Helper to load a fixed-size array from hex
fn hex_to_array_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex_to_bytes(hex_str);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    arr
}

fn hex_to_array_64(hex_str: &str) -> [u8; 64] {
    let bytes = hex_to_bytes(hex_str);
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes[..64]);
    arr
}

fn hex_to_array_128(hex_str: &str) -> [u8; 128] {
    let bytes = hex_to_bytes(hex_str);
    let mut arr = [0u8; 128];
    arr.copy_from_slice(&bytes[..128]);
    arr
}

/// Load the real test vector from Vikram's circuit output
fn load_real_test_vector() -> (ProofSubmission, Vec<u8>) {
    // Load the JSON test vector
    let json_str = include_str!("../tests/transfer_valid_1in_1out.json");
    let data: serde_json::Value = serde_json::from_str(json_str)
        .expect("Failed to parse test vector JSON");

    // Parse proof points
    let proof_a = hex_to_array_64(data["proof"]["a"].as_str().unwrap());
    let proof_b = hex_to_array_128(data["proof"]["b"].as_str().unwrap());
    let proof_c = hex_to_array_64(data["proof"]["c"].as_str().unwrap());

    let proof = Groth16Proof {
        a: proof_a,
        b: proof_b,
        c: proof_c,
    };

    // Parse public inputs
    let merkle_root = hex_to_array_32(
        data["public_inputs"]["merkle_root"].as_str().unwrap()
    );

    let nullifiers: Vec<[u8; 32]> = data["public_inputs"]["nullifiers"]
        .as_array().unwrap()
        .iter()
        .map(|n| hex_to_array_32(n.as_str().unwrap()))
        .collect();

    let output_commitments: Vec<[u8; 32]> = data["public_inputs"]["output_commitments"]
        .as_array().unwrap()
        .iter()
        .map(|c| hex_to_array_32(c.as_str().unwrap()))
        .collect();

    let asset_id = hex_to_array_32(
        data["public_inputs"]["asset_id"].as_str().unwrap()
    );

    let fee_commitment = hex_to_array_32(
        data["public_inputs"]["fee_commitment"].as_str().unwrap()
    );

    let inputs = TransferPublicInputs {
        merkle_root,
        nullifiers,
        output_commitments,
        asset_id,
        fee_commitment,
    };

    let submission = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
        proof,
        inputs,
    }));

    // Load the verifying key binary
    let vk_bytes = include_bytes!("../tests/transfer_verifying_key.bin").to_vec();

    (submission, vk_bytes)
}


// REAL GROTH16 VERIFICATION TEST


#[test]
fn verify_real_groth16_proof_from_fixture() {
    new_test_ext().execute_with(|| {
        let (submission, vk_bytes) = load_real_test_vector();

        // Store the real verifying key
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(),
            ProofType::Groth16Transfer,
            vk_bytes,
        ));

        // Submit the real proof for verification
        let result = ProofVerifier::submit_proof(
            RuntimeOrigin::signed(1),
            submission,
        );

        // This should succeed if the proof and VK are valid
        assert_ok!(result);

        // Verify the counters updated
        assert_eq!(ProofVerifier::proof_count(), 1);
        assert_eq!(ProofVerifier::proof_count_by_type(ProofType::Groth16Transfer), 1);

        // Verify the event was emitted
        System::assert_last_event(
            Event::<Test>::ProofVerified {
                submitter: 1,
                proof_type: ProofType::Groth16Transfer,
            }
            .into(),
        );
    });
}

#[test]
fn reject_tampered_groth16_proof() {
    new_test_ext().execute_with(|| {
        let (submission, vk_bytes) = load_real_test_vector();

        // Store the real verifying key
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(),
            ProofType::Groth16Transfer,
            vk_bytes,
        ));

        // Tamper with the proof: flip a byte in point A
        if let ProofSubmission::ShieldedTransfer(data) = submission {
            let mut tampered_proof = data.proof.clone();
            tampered_proof.a[0] ^= 0xFF; // flip bits

            let tampered = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
                proof: tampered_proof,
                inputs: data.inputs.clone(),
            }));

            // This should fail because the proof is invalid
            assert_noop!(
                ProofVerifier::submit_proof(RuntimeOrigin::signed(1), tampered),
                Error::<Test>::InvalidProofFormat, // deserialization will fail for bad curve point
            );
        }
    });
}


//EXISTING STUB TESTS (still valid for Halo2 and Nova)


#[test]
fn set_verifying_key_works() {
    new_test_ext().execute_with(|| {
        let key = vec![1u8; 100];
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(),
            ProofType::Groth16Transfer,
            key.clone(),
        ));
        let stored = ProofVerifier::verifying_keys(ProofType::Groth16Transfer).unwrap();
        assert_eq!(stored.to_vec(), key);
    });
}

#[test]
fn set_verifying_key_rejects_non_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ProofVerifier::set_verifying_key(
                RuntimeOrigin::signed(1),
                ProofType::Groth16Transfer,
                vec![1u8; 100],
            ),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

#[test]
fn set_verifying_key_rejects_oversized() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ProofVerifier::set_verifying_key(
                RuntimeOrigin::root(),
                ProofType::Groth16Transfer,
                vec![0u8; 51201],
            ),
            Error::<Test>::VerifyingKeyTooLarge,
        );
    });
}

#[test]
fn set_verifying_key_emits_event() {
    new_test_ext().execute_with(|| {
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(),
            ProofType::Halo2Membership,
            vec![1u8; 50],
        ));
        System::assert_last_event(
            Event::<Test>::VerifyingKeyUpdated { proof_type: ProofType::Halo2Membership }.into(),
        );
    });
}

#[test]
fn submit_groth16_fails_without_key() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ProofVerifier::submit_proof(RuntimeOrigin::signed(1), make_transfer()),
            Error::<Test>::NoVerifyingKey,
        );
    });
}

#[test]
fn submit_groth16_rejects_too_many_inputs() {
    new_test_ext().execute_with(|| {
        // Need a real VK for bounds check to proceed to that point
        let (_, vk_bytes) = load_real_test_vector();
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(), ProofType::Groth16Transfer, vk_bytes,
        ));
        let sub = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
            proof: Groth16Proof {
                a: [1u8; G1_UNCOMPRESSED_SIZE],
                b: [2u8; G2_UNCOMPRESSED_SIZE],
                c: [3u8; G1_UNCOMPRESSED_SIZE],
            },
            inputs: TransferPublicInputs {
                merkle_root: [0xAA; 32],
                nullifiers: vec![[0xBB; 32]; 9],
                output_commitments: vec![[0xDD; 32]],
                asset_id: NATIVE_ASSET_ID,
                fee_commitment: [0xFF; 32],
            },
        }));
        assert_noop!(
            ProofVerifier::submit_proof(RuntimeOrigin::signed(1), sub),
            Error::<Test>::TooManyInputs,
        );
    });
}

#[test]
fn submit_groth16_rejects_too_many_outputs() {
    new_test_ext().execute_with(|| {
        let (_, vk_bytes) = load_real_test_vector();
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(), ProofType::Groth16Transfer, vk_bytes,
        ));
        let sub = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
            proof: Groth16Proof {
                a: [1u8; G1_UNCOMPRESSED_SIZE],
                b: [2u8; G2_UNCOMPRESSED_SIZE],
                c: [3u8; G1_UNCOMPRESSED_SIZE],
            },
            inputs: TransferPublicInputs {
                merkle_root: [0xAA; 32],
                nullifiers: vec![[0xBB; 32]],
                output_commitments: vec![[0xDD; 32]; 9],
                asset_id: NATIVE_ASSET_ID,
                fee_commitment: [0xFF; 32],
            },
        }));
        assert_noop!(
            ProofVerifier::submit_proof(RuntimeOrigin::signed(1), sub),
            Error::<Test>::TooManyOutputs,
        );
    });
}

// -- Halo2 --

#[test]
fn submit_halo2_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(), ProofType::Halo2Membership, vec![1u8; 300],
        ));
        assert_ok!(ProofVerifier::submit_proof(RuntimeOrigin::signed(2), make_membership()));
        assert_eq!(ProofVerifier::proof_count(), 1);
        assert_eq!(ProofVerifier::proof_count_by_type(ProofType::Halo2Membership), 1);
    });
}

#[test]
fn submit_halo2_rejects_empty_proof() {
    new_test_ext().execute_with(|| {
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(), ProofType::Halo2Membership, vec![1u8; 300],
        ));
        let sub = ProofSubmission::ValidatorMembership {
            proof: Halo2Proof { proof_bytes: vec![] },
            inputs: MembershipPublicInputs { validator_root: [0x11; 32], epoch: 1, slot: 10 },
        };
        assert_noop!(
            ProofVerifier::submit_proof(RuntimeOrigin::signed(2), sub),
            Error::<Test>::InvalidProofFormat,
        );
    });
}

// -- Nova --

#[test]
fn submit_nova_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(), ProofType::NovaOrigin, vec![1u8; 400],
        ));
        assert_ok!(ProofVerifier::submit_proof(RuntimeOrigin::signed(3), make_lineage()));
        assert_eq!(ProofVerifier::proof_count(), 1);
        assert_eq!(ProofVerifier::proof_count_by_type(ProofType::NovaOrigin), 1);
    });
}

#[test]
fn submit_nova_rejects_empty_accumulator() {
    new_test_ext().execute_with(|| {
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(), ProofType::NovaOrigin, vec![1u8; 400],
        ));
        let sub = ProofSubmission::StateLineage {
            proof: NovaProof { accumulator: vec![], block_height: 5 },
            inputs: OriginPublicInputs {
                prev_state_root: [0x22; 32], new_state_root: [0x33; 32],
                block_height: 5, genesis_hash: [0x00; 32],
            num_steps: 1,
            },
        };
        assert_noop!(
            ProofVerifier::submit_proof(RuntimeOrigin::signed(3), sub),
            Error::<Test>::InvalidProofFormat,
        );
    });
}

#[test]
fn submit_nova_rejects_zero_block_height() {
    new_test_ext().execute_with(|| {
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(), ProofType::NovaOrigin, vec![1u8; 400],
        ));
        let sub = ProofSubmission::StateLineage {
            proof: NovaProof { accumulator: vec![1, 2, 3], block_height: 5 },
            inputs: OriginPublicInputs {
                prev_state_root: [0x22; 32], new_state_root: [0x33; 32],
                block_height: 0, genesis_hash: [0x00; 32],
            num_steps: 1,
            },
        };
        assert_noop!(
            ProofVerifier::submit_proof(RuntimeOrigin::signed(3), sub),
            Error::<Test>::InvalidProofFormat,
        );
    });
}

// -- Counters --

#[test]
fn proof_counters_track_across_types() {
    new_test_ext().execute_with(|| {
        // Use real VK for groth16, dummy for others
        let (_, vk_bytes) = load_real_test_vector();
        assert_ok!(ProofVerifier::set_verifying_key(RuntimeOrigin::root(), ProofType::Groth16Transfer, vk_bytes));
        assert_ok!(ProofVerifier::set_verifying_key(RuntimeOrigin::root(), ProofType::Halo2Membership, vec![2u8; 300]));
        assert_ok!(ProofVerifier::set_verifying_key(RuntimeOrigin::root(), ProofType::NovaOrigin, vec![3u8; 400]));

        // Real groth16 proof
        let (real_transfer, _) = load_real_test_vector();
        assert_ok!(ProofVerifier::submit_proof(RuntimeOrigin::signed(1), real_transfer));
        assert_ok!(ProofVerifier::submit_proof(RuntimeOrigin::signed(2), make_membership()));
        assert_ok!(ProofVerifier::submit_proof(RuntimeOrigin::signed(3), make_lineage()));

        assert_eq!(ProofVerifier::proof_count(), 3);
        assert_eq!(ProofVerifier::proof_count_by_type(ProofType::Groth16Transfer), 1);
        assert_eq!(ProofVerifier::proof_count_by_type(ProofType::Halo2Membership), 1);
        assert_eq!(ProofVerifier::proof_count_by_type(ProofType::NovaOrigin), 1);
    });
}

// -- Key overwrite --

#[test]
fn verifying_key_can_be_overwritten() {
    new_test_ext().execute_with(|| {
        assert_ok!(ProofVerifier::set_verifying_key(RuntimeOrigin::root(), ProofType::Groth16Transfer, vec![1u8; 100]));
        assert_ok!(ProofVerifier::set_verifying_key(RuntimeOrigin::root(), ProofType::Groth16Transfer, vec![2u8; 200]));
        let stored = ProofVerifier::verifying_keys(ProofType::Groth16Transfer).unwrap();
        assert_eq!(stored.to_vec(), vec![2u8; 200]);
    });
}