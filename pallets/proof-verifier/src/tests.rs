use crate::{mock::*, Error, Event};
use frame_support::{assert_noop, assert_ok};
use zk_types::*;

// ── inline proof generation ──────────────────────────────────────────────────
// The old JSON/bin fixtures were generated from the PLACEHOLDER circuit
// (field-addition based, 5 public inputs).  The fixed-shape Poseidon circuit
// always emits exactly 19 public inputs so those fixtures can never verify.
// Instead we generate a real proof once per test-binary run via OnceLock.
// This is the same approach as groth16_prover::tests::test_full_prove_verify_cycle.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use std::sync::OnceLock;
use transfer_circuit::{Note, MerklePath, TransferCircuit, TREE_DEPTH};
use zc_crypto::poseidon::poseidon_hash;

struct ProofFixture {
    groth16_proof: Groth16Proof,
    transfer_inputs: TransferPublicInputs,
    vk_bytes: Vec<u8>,
    proving_key: ark_groth16::ProvingKey<Bn254>,
}

static FIXTURE: OnceLock<ProofFixture> = OnceLock::new();

fn get_fixture() -> &'static ProofFixture {
    FIXTURE.get_or_init(|| {
        let mut rng = ark_std::rand::thread_rng();

        // Trusted setup — fixed-shape circuit (MAX_INPUTS=8, MAX_OUTPUTS=8, TREE_DEPTH=32)
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            TransferCircuit::default(), &mut rng,
        )
        .expect("Groth16 circuit_specific_setup failed");

        let mut vk_bytes = Vec::new();
        vk.serialize_uncompressed(&mut vk_bytes).expect("VK serialisation failed");

        // 1-in 1-out transfer with real Poseidon commitments / nullifiers
        let circuit = TransferCircuit::test_circuit();

        let merkle_root = fr_bytes(circuit.merkle_root);
        let nullifier_0 = fr_bytes(*circuit.nullifiers.first().expect("nullifier"));
        let commitment_0 = fr_bytes(*circuit.output_commitments.first().expect("commitment"));
        let asset_id = fr_bytes(circuit.asset_id);
        let fee = fr_bytes(circuit.fee_commitment);

        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
            .expect("Groth16 prove failed");

        let mut proof_a = [0u8; G1_UNCOMPRESSED_SIZE];
        let mut proof_b = [0u8; G2_UNCOMPRESSED_SIZE];
        let mut proof_c = [0u8; G1_UNCOMPRESSED_SIZE];
        proof.a.serialize_uncompressed(&mut proof_a[..]).unwrap();
        proof.b.serialize_uncompressed(&mut proof_b[..]).unwrap();
        proof.c.serialize_uncompressed(&mut proof_c[..]).unwrap();

        ProofFixture {
            groth16_proof: Groth16Proof { a: proof_a, b: proof_b, c: proof_c },
            transfer_inputs: TransferPublicInputs {
                merkle_root,
                nullifiers: vec![nullifier_0],
                output_commitments: vec![commitment_0],
                asset_id,
                fee_commitment: fee,
            },
            vk_bytes,
            proving_key: pk,
        }
    })
}

fn fr_bytes(fr: Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fr.serialize_uncompressed(&mut bytes[..]).unwrap();
    bytes
}

fn make_transfer_submission() -> (ProofSubmission, Vec<u8>) {
    let f = get_fixture();
    (
        ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
            proof: f.groth16_proof.clone(),
            inputs: f.transfer_inputs.clone(),
            memos: vec![],  // no encrypted memos in unit tests
        })),
        f.vk_bytes.clone(),
    )
}

// ── helper builders ──────────────────────────────────────────────────────────

#[cfg(feature = "experimental")]
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

#[cfg(feature = "experimental")]
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

// ── REAL GROTH16 VERIFICATION (E2E) ─────────────────────────────────────────

/// Verifies that a real Groth16 proof from the current Poseidon-based
/// TransferCircuit passes on-chain verification.
///
/// This replaces the old fixture-based test which used a placeholder circuit
/// (field-addition commitments, 5 public inputs). The fixed-shape circuit
/// always emits 19 public inputs; the old 5-input VK cannot verify them.
#[test]
fn verify_real_groth16_proof_from_fixture() {
    let (submission, vk_bytes) = make_transfer_submission();
    let merkle_root = get_fixture().transfer_inputs.merkle_root;
    new_test_ext().execute_with(|| {
        // shielded-assets requires a registered root; use the circuit's actual root.
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), merkle_root));
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(),
            ProofType::Groth16Transfer,
            vk_bytes,
        ));
        assert_ok!(ProofVerifier::submit_proof(RuntimeOrigin::signed(1), submission));
        assert_eq!(ProofVerifier::proof_count(), 1);
        assert_eq!(ProofVerifier::proof_count_by_type(ProofType::Groth16Transfer), 1);
        System::assert_last_event(
            Event::<Test>::ProofVerified {
                submitter: 1,
                proof_type: ProofType::Groth16Transfer,
            }
            .into(),
        );
    });
}

/// Verifies that a tampered proof (single bit flipped in point A) is rejected.
#[test]
fn reject_tampered_groth16_proof() {
    let (submission, vk_bytes) = make_transfer_submission();
    new_test_ext().execute_with(|| {
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(),
            ProofType::Groth16Transfer,
            vk_bytes,
        ));
        if let ProofSubmission::ShieldedTransfer(data) = submission {
            let mut tampered = data.proof.clone();
            tampered.a[0] ^= 0xFF;
            let bad = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
                proof: tampered,
                inputs: data.inputs.clone(),
                memos: vec![],
            }));
            // Flipping bits in a compressed G1 point makes it a non-curve-point;
            // deserialize_uncompressed rejects it → InvalidProofFormat.
            assert_noop!(
                ProofVerifier::submit_proof(RuntimeOrigin::signed(1), bad),
                Error::<Test>::InvalidProofFormat,
            );
        }
    });
}

/// C-01/H-13: a public input encoded as (field_element + BN254_ORDER) must be
/// rejected, not silently reduced mod p (double-spend vector).
#[test]
fn reject_non_canonical_public_input() {
    // BN254 scalar field order p (little-endian 32 bytes)
    // p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    let bn254_order_le: [u8; 32] = [
        0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43,
        0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
        0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
        0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
    ];

    let (submission, vk_bytes) = make_transfer_submission();
    new_test_ext().execute_with(|| {
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(),
            ProofType::Groth16Transfer,
            vk_bytes,
        ));
        // Inject the field order as the merkle_root — this is >= p, non-canonical
        if let ProofSubmission::ShieldedTransfer(data) = submission {
            let bad = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
                proof: data.proof.clone(),
                inputs: TransferPublicInputs {
                    merkle_root: bn254_order_le,
                    ..data.inputs.clone()
                },
                memos: vec![],
            }));
            assert_noop!(
                ProofVerifier::submit_proof(RuntimeOrigin::signed(1), bad),
                Error::<Test>::InvalidPublicInput,
            );
        }
    });
}

// ── EXISTING TESTS (unchanged) ───────────────────────────────────────────────

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
        let (submission, _) = make_transfer_submission();
        assert_noop!(
            ProofVerifier::submit_proof(RuntimeOrigin::signed(1), submission),
            Error::<Test>::NoVerifyingKey,
        );
    });
}

#[test]
fn submit_groth16_rejects_too_many_inputs() {
    let (_, vk_bytes) = make_transfer_submission();
    new_test_ext().execute_with(|| {
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(), ProofType::Groth16Transfer, vk_bytes,
        ));
        let f = get_fixture();
        let sub = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
            proof: f.groth16_proof.clone(),
            inputs: TransferPublicInputs {
                merkle_root: f.transfer_inputs.merkle_root,
                nullifiers: vec![[0xBB; 32]; 9],
                output_commitments: vec![[0xDD; 32]],
                asset_id: NATIVE_ASSET_ID,
                fee_commitment: [0u8; 32],
            },
            memos: vec![],
        }));
        assert_noop!(
            ProofVerifier::submit_proof(RuntimeOrigin::signed(1), sub),
            Error::<Test>::TooManyInputs,
        );
    });
}

#[test]
fn submit_groth16_rejects_too_many_outputs() {
    let (_, vk_bytes) = make_transfer_submission();
    new_test_ext().execute_with(|| {
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(), ProofType::Groth16Transfer, vk_bytes,
        ));
        let f = get_fixture();
        let sub = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
            proof: f.groth16_proof.clone(),
            inputs: TransferPublicInputs {
                merkle_root: f.transfer_inputs.merkle_root,
                nullifiers: vec![[0xBB; 32]],
                output_commitments: vec![[0xDD; 32]; 9],
                asset_id: NATIVE_ASSET_ID,
                fee_commitment: [0u8; 32],
            },
            memos: vec![],
        }));
        assert_noop!(
            ProofVerifier::submit_proof(RuntimeOrigin::signed(1), sub),
            Error::<Test>::TooManyOutputs,
        );
    });
}

// -- Halo2 (experimental only) --

#[cfg(feature = "experimental")]
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

#[cfg(feature = "experimental")]
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

// -- Nova (experimental only) --

#[cfg(feature = "experimental")]
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

#[cfg(feature = "experimental")]
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

#[cfg(feature = "experimental")]
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

/// Production runtime gate: every non-transfer variant must return
/// UnsupportedProofType without reaching any stub logic.
/// Runs only when the `experimental` feature is absent (i.e., in production builds).
#[cfg(not(feature = "experimental"))]
#[test]
fn non_transfer_proofs_rejected_on_production_runtime() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ProofVerifier::submit_proof(
                RuntimeOrigin::signed(1),
                ProofSubmission::ValidatorMembership {
                    proof: Halo2Proof { proof_bytes: vec![1, 2, 3] },
                    inputs: MembershipPublicInputs {
                        validator_root: [0x11; 32],
                        epoch: 1,
                        slot: 10,
                    },
                },
            ),
            Error::<Test>::UnsupportedProofType,
        );

        assert_noop!(
            ProofVerifier::submit_proof(
                RuntimeOrigin::signed(1),
                ProofSubmission::StateLineage {
                    proof: NovaProof { accumulator: vec![10, 20, 30], block_height: 5 },
                    inputs: OriginPublicInputs {
                        prev_state_root: [0x22; 32],
                        new_state_root: [0x33; 32],
                        block_height: 5,
                        genesis_hash: [0x00; 32],
                        num_steps: 1,
                    },
                },
            ),
            Error::<Test>::UnsupportedProofType,
        );

        assert_noop!(
            ProofVerifier::submit_proof(
                RuntimeOrigin::signed(1),
                ProofSubmission::Slashing {
                    proof: Groth16Proof { a: [1u8; 64], b: [2u8; 128], c: [3u8; 64] },
                    inputs: SlashingPublicInputs {
                        validator_root: [0x44; 32],
                        nullifier: [0x55; 32],
                        block_hash_1: [0x66; 32],
                        block_hash_2: [0x77; 32],
                    },
                },
            ),
            Error::<Test>::UnsupportedProofType,
        );

        // No side-effects: counters must remain at zero.
        assert_eq!(ProofVerifier::proof_count(), 0);
    });
}

// -- Counters (experimental only: needs all three proof types) --

#[cfg(feature = "experimental")]
#[test]
fn proof_counters_track_across_types() {
    let (real_transfer, vk_bytes) = make_transfer_submission();
    let merkle_root = get_fixture().transfer_inputs.merkle_root;
    new_test_ext().execute_with(|| {
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), merkle_root));
        assert_ok!(ProofVerifier::set_verifying_key(RuntimeOrigin::root(), ProofType::Groth16Transfer, vk_bytes));
        assert_ok!(ProofVerifier::set_verifying_key(RuntimeOrigin::root(), ProofType::Halo2Membership, vec![2u8; 300]));
        assert_ok!(ProofVerifier::set_verifying_key(RuntimeOrigin::root(), ProofType::NovaOrigin, vec![3u8; 400]));

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

// ── END-TO-END: real proof → shielded-assets state mutation ─────────────────

/// Full integration: a real Groth16 proof flows through submit_proof into
/// shielded-assets.  Asserts that the real nullifier is recorded, the real
/// commitment is appended, dummy zero-slots are NOT recorded, and counters
/// are correct.  Public inputs come from the prover's circuit construction.
#[test]
fn e2e_real_proof_mutates_shielded_state() {
    let f = get_fixture();
    let merkle_root      = f.transfer_inputs.merkle_root;
    let real_nullifier   = f.transfer_inputs.nullifiers[0];
    let real_commitment  = f.transfer_inputs.output_commitments[0];

    new_test_ext().execute_with(|| {
        // Register the exact Merkle root the circuit was proved against.
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), merkle_root));
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(),
            ProofType::Groth16Transfer,
            f.vk_bytes.clone(),
        ));

        let submission = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
            proof: f.groth16_proof.clone(),
            inputs: f.transfer_inputs.clone(),
            memos: vec![],
        }));
        assert_ok!(ProofVerifier::submit_proof(RuntimeOrigin::signed(1), submission));

        // Real nullifier must be in the spent set.
        assert!(ShieldedAssets::nullifier_exists(real_nullifier).is_some());
        // Dummy sentinel ([0u8;32]) must NOT be in the spent set.
        assert!(ShieldedAssets::nullifier_exists([0u8; 32]).is_none());
        assert_eq!(ShieldedAssets::nullifier_count(), 1);

        // Real commitment must be at index 0.
        assert_eq!(ShieldedAssets::commitments(0), Some(real_commitment));
        assert_eq!(ShieldedAssets::commitment_count(), 1);

        // proof-verifier counters also updated.
        assert_eq!(ProofVerifier::proof_count(), 1);
        assert_eq!(ProofVerifier::proof_count_by_type(ProofType::Groth16Transfer), 1);
    });
}

/// Tampered proof must be rejected and leave shielded-assets state completely
/// unchanged (no nullifiers, no commitments).
#[test]
fn e2e_tampered_proof_leaves_state_unchanged() {
    let f = get_fixture();
    let merkle_root = f.transfer_inputs.merkle_root;

    new_test_ext().execute_with(|| {
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), merkle_root));
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(),
            ProofType::Groth16Transfer,
            f.vk_bytes.clone(),
        ));

        let mut tampered = f.groth16_proof.clone();
        tampered.a[0] ^= 0xFF;
        let bad = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
            proof: tampered,
            inputs: f.transfer_inputs.clone(),
            memos: vec![],
        }));
        assert_noop!(
            ProofVerifier::submit_proof(RuntimeOrigin::signed(1), bad),
            Error::<Test>::InvalidProofFormat,
        );

        // State must be completely unchanged.
        assert_eq!(ShieldedAssets::nullifier_count(), 0);
        assert_eq!(ShieldedAssets::commitment_count(), 0);
        assert_eq!(ProofVerifier::proof_count(), 0);
    });
}

// ── SHIELD → TRANSFER E2E (byte-identity proof) ─────────────────────────────

/// Proves that the on-chain shield commitment and the circuit's Note::commitment()
/// are byte-identical: a note shielded via shield() is spendable by the real
/// transfer circuit without any additional conversion.
///
/// Protocol:
/// 1. Alice calls shield() with (value=100, pk_alice, blinding).
///    pallet-shielded-assets inserts cm_on_chain = note_commitment(pk_alice, 100, 0, blinding).
/// 2. We compute cm_circuit = Note { owner_pubkey, value, asset_id, blinding }.commitment().
///    Assert cm_on_chain == cm_circuit (same 32 bytes — proves Poseidon arity/order match).
/// 3. Build the Merkle root over cm_circuit (TREE_DEPTH levels, all siblings zero).
///    Register the root on-chain via update_merkle_root.
/// 4. Generate a real Groth16 transfer proof spending the exact note.
/// 5. Submit via submit_proof — the proof verifies; nullifier is recorded;
///    Bob's commitment is appended.
/// 6. A tampered proof (bit-flip in proof.a) is rejected; state is unchanged.
#[test]
fn shield_to_transfer_proves_same_commitment_byte_identical() {
    // ── deterministic note parameters ──────────────────────────────────────────
    let sk_alice = Fr::from(42u64);
    let owner_pubkey = poseidon_hash(&[sk_alice]);   // Poseidon_t2(sk)
    let value: u64 = 100;
    let asset_id_fr = Fr::from(0u64);               // NATIVE_ASSET_ID
    let blinding_fr = Fr::from(99u64);

    let pk_alice_bytes = fr_bytes(owner_pubkey);
    let blinding_bytes = fr_bytes(blinding_fr);

    // ── circuit-side Note and derived values ───────────────────────────────────
    let input_note = Note { value, asset_id: asset_id_fr, blinding: blinding_fr, owner_pubkey };
    let input_cm = input_note.commitment();
    let input_cm_bytes = fr_bytes(input_cm);

    let input_nullifier = input_note.nullifier(sk_alice);
    let input_nullifier_bytes = fr_bytes(input_nullifier);

    // Merkle root: leaf at position 0, all siblings zero, TREE_DEPTH levels up.
    let merkle_root_fr = {
        let mut cur = input_cm;
        for _ in 0..TREE_DEPTH {
            cur = poseidon_hash(&[cur, Fr::from(0u64)]);
        }
        cur
    };
    let merkle_root_bytes = fr_bytes(merkle_root_fr);

    // Output note for Bob — same value, independent deterministic key (no spend-authority check on outputs).
    let output_note = Note {
        value,
        asset_id: asset_id_fr,
        blinding: Fr::from(12345u64),
        owner_pubkey: Fr::from(777u64),
    };
    let output_cm = output_note.commitment();
    let output_cm_bytes = fr_bytes(output_cm);

    // ── generate real Groth16 proof using the shared proving key ───────────────
    let circuit = TransferCircuit {
        input_notes: vec![input_note],
        output_notes: vec![output_note],
        merkle_paths: vec![MerklePath::dummy()],
        secret_keys: vec![sk_alice],
        merkle_root: merkle_root_fr,
        nullifiers: vec![input_nullifier],
        output_commitments: vec![output_cm],
        asset_id: asset_id_fr,
        fee_commitment: Fr::from(0u64),
    };

    let mut rng = ark_std::rand::thread_rng();
    let proof = Groth16::<Bn254>::prove(&get_fixture().proving_key, circuit, &mut rng)
        .expect("Groth16 prove failed");

    let mut proof_a = [0u8; G1_UNCOMPRESSED_SIZE];
    let mut proof_b = [0u8; G2_UNCOMPRESSED_SIZE];
    let mut proof_c = [0u8; G1_UNCOMPRESSED_SIZE];
    proof.a.serialize_uncompressed(&mut proof_a[..]).unwrap();
    proof.b.serialize_uncompressed(&mut proof_b[..]).unwrap();
    proof.c.serialize_uncompressed(&mut proof_c[..]).unwrap();

    let valid_submission = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
        proof: Groth16Proof { a: proof_a, b: proof_b, c: proof_c },
        inputs: TransferPublicInputs {
            merkle_root: merkle_root_bytes,
            nullifiers: vec![input_nullifier_bytes],
            output_commitments: vec![output_cm_bytes],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0u8; 32],
        },
        memos: vec![],
    }));

    let mut tampered_proof_a = proof_a;
    tampered_proof_a[0] ^= 0xFF;
    let tampered_submission = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
        proof: Groth16Proof { a: tampered_proof_a, b: proof_b, c: proof_c },
        inputs: TransferPublicInputs {
            merkle_root: merkle_root_bytes,
            nullifiers: vec![input_nullifier_bytes],
            output_commitments: vec![output_cm_bytes],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0u8; 32],
        },
        memos: vec![],
    }));

    let vk_bytes = get_fixture().vk_bytes.clone();

    // Alice starts with 1_000_000 units.
    new_test_ext_with_balances(vec![(1, 1_000_000)]).execute_with(|| {
        // Step 1: Alice shields 100 units.
        assert_ok!(ShieldedAssets::shield(
            RuntimeOrigin::signed(1),
            100u128,
            pk_alice_bytes,
            blinding_bytes,
        ));

        // CORE INVARIANT: the on-chain commitment must be byte-identical to
        // Note::commitment() — same Poseidon arity (t=5) and argument order.
        let on_chain_cm = ShieldedAssets::commitments(0).expect("commitment at index 0");
        assert_eq!(
            on_chain_cm, input_cm_bytes,
            "on-chain shield commitment must equal circuit Note::commitment() byte-for-byte"
        );
        assert_eq!(ShieldedAssets::commitment_count(), 1);

        // Step 2: Register the Merkle root that the circuit was proved against.
        assert_ok!(ShieldedAssets::update_merkle_root(
            RuntimeOrigin::root(),
            merkle_root_bytes,
        ));

        // Step 3: Install VK and submit the real transfer proof.
        assert_ok!(ProofVerifier::set_verifying_key(
            RuntimeOrigin::root(),
            ProofType::Groth16Transfer,
            vk_bytes,
        ));
        assert_ok!(ProofVerifier::submit_proof(RuntimeOrigin::signed(1), valid_submission));

        // Step 4: Assert resulting state.
        // Alice's input nullifier is now in the spent set.
        assert!(ShieldedAssets::nullifier_exists(input_nullifier_bytes).is_some());
        assert!(ShieldedAssets::nullifier_exists([0u8; 32]).is_none());
        assert_eq!(ShieldedAssets::nullifier_count(), 1);

        // Bob's output commitment was appended at index 1 (after Alice's shield at 0).
        assert_eq!(ShieldedAssets::commitments(1), Some(output_cm_bytes));
        assert_eq!(ShieldedAssets::commitment_count(), 2);

        assert_eq!(ProofVerifier::proof_count(), 1);
        assert_eq!(ProofVerifier::proof_count_by_type(ProofType::Groth16Transfer), 1);

        // Step 5: Tampered proof is rejected; state does not change again.
        assert_noop!(
            ProofVerifier::submit_proof(RuntimeOrigin::signed(1), tampered_submission),
            Error::<Test>::InvalidProofFormat,
        );

        // Counters unchanged after the rejected submission.
        assert_eq!(ProofVerifier::proof_count(), 1);
        assert_eq!(ShieldedAssets::nullifier_count(), 1);
        assert_eq!(ShieldedAssets::commitment_count(), 2);
    });
}
