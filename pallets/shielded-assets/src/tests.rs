use crate::{mock::*, Error, Event};
use frame_support::{assert_noop, assert_ok};
use zk_types::*;
use zc_crypto::commitment::note_commitment;

const DUMMY: Hash256 = [0u8; 32];

const ALICE: u64 = 1;
const INIT_BALANCE: Balance = 1_000_000;
const ROOT: Hash256 = [0xAA; 32];

fn real_inputs() -> TransferPublicInputs {
    TransferPublicInputs {
        merkle_root: ROOT,
        nullifiers: vec![[0xBB; 32], [0xCC; 32]],
        output_commitments: vec![[0xDD; 32], [0xEE; 32]],
        asset_id: NATIVE_ASSET_ID,
        fee_commitment: [0xFF; 32],
    }
}

// ── Merkle root / no-root guard ──────────────────────────────────────────────

#[test]
fn transfer_fails_without_merkle_root() {
    // NoMerkleRoot: no genesis root set, transfer must be rejected.
    new_test_ext().execute_with(|| {
        let inputs = real_inputs();
        assert_noop!(
            ShieldedAssets::do_process_transfer_pub(&inputs),
            Error::<Test>::InvalidMerkleRoot,
        );
    });
}

#[test]
fn genesis_sets_merkle_root() {
    new_test_ext_with_root(ROOT).execute_with(|| {
        assert_eq!(ShieldedAssets::current_merkle_root(), Some(ROOT));
    });
}

#[test]
fn transfer_passes_with_genesis_root() {
    new_test_ext_with_root(ROOT).execute_with(|| {
        assert_ok!(ShieldedAssets::do_process_transfer_pub(&real_inputs()));
        assert_eq!(ShieldedAssets::commitment_count(), 2);
        assert_eq!(ShieldedAssets::nullifier_count(), 2);
    });
}

// ── Root validation ──────────────────────────────────────────────────────────

#[test]
fn transfer_checks_merkle_root() {
    new_test_ext_with_root(ROOT).execute_with(|| {
        let mut bad = real_inputs();
        bad.merkle_root = [0x99; 32];
        assert_noop!(
            ShieldedAssets::do_process_transfer_pub(&bad),
            Error::<Test>::InvalidMerkleRoot,
        );
    });
}

#[test]
fn update_merkle_root_works() {
    new_test_ext().execute_with(|| {
        let root = [0xAB; 32];
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), root));
        assert_eq!(ShieldedAssets::current_merkle_root(), Some(root));
    });
}

#[test]
fn update_merkle_root_rejects_non_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ShieldedAssets::update_merkle_root(RuntimeOrigin::signed(1), [0xAB; 32]),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

#[test]
fn update_merkle_root_keeps_history() {
    new_test_ext().execute_with(|| {
        let root1 = [0x01; 32];
        let root2 = [0x02; 32];
        let root3 = [0x03; 32];
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), root1));
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), root2));
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), root3));
        assert_eq!(ShieldedAssets::current_merkle_root(), Some(root3));

        let mut i1 = real_inputs();
        i1.merkle_root = root1;
        i1.nullifiers = vec![[0x10; 32]];
        assert_ok!(ShieldedAssets::do_process_transfer_pub(&i1));

        let mut i2 = real_inputs();
        i2.merkle_root = root2;
        i2.nullifiers = vec![[0x20; 32]];
        assert_ok!(ShieldedAssets::do_process_transfer_pub(&i2));
    });
}

#[test]
fn update_merkle_root_emits_event() {
    new_test_ext().execute_with(|| {
        let root = [0xAB; 32];
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), root));
        System::assert_last_event(Event::<Test>::MerkleRootUpdated { root }.into());
    });
}

// ── Double-spend ─────────────────────────────────────────────────────────────

#[test]
fn double_spend_rejected() {
    new_test_ext_with_root(ROOT).execute_with(|| {
        let inputs = real_inputs();
        assert_ok!(ShieldedAssets::do_process_transfer_pub(&inputs));
        assert_noop!(
            ShieldedAssets::do_process_transfer_pub(&inputs),
            Error::<Test>::NullifierAlreadySpent,
        );
    });
}

// ── Commitment appending ─────────────────────────────────────────────────────

#[test]
fn commitments_appended_in_order() {
    new_test_ext_with_root(ROOT).execute_with(|| {
        assert_ok!(ShieldedAssets::do_process_transfer_pub(&real_inputs()));
        assert_eq!(ShieldedAssets::commitments(0), Some([0xDD; 32]));
        assert_eq!(ShieldedAssets::commitments(1), Some([0xEE; 32]));
        assert_eq!(ShieldedAssets::commitment_count(), 2);

        let inputs2 = TransferPublicInputs {
            merkle_root: ROOT,
            nullifiers: vec![[0x11; 32]],
            output_commitments: vec![[0x22; 32], [0x33; 32], [0x44; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        };
        assert_ok!(ShieldedAssets::do_process_transfer_pub(&inputs2));
        assert_eq!(ShieldedAssets::commitments(2), Some([0x22; 32]));
        assert_eq!(ShieldedAssets::commitments(3), Some([0x33; 32]));
        assert_eq!(ShieldedAssets::commitments(4), Some([0x44; 32]));
        assert_eq!(ShieldedAssets::commitment_count(), 5);
    });
}

// ── Dummy-slot filtering ─────────────────────────────────────────────────────

#[test]
fn dummy_nullifiers_are_skipped() {
    // Circuit pads to MAX_INPUTS with [0u8;32]. These must NOT be recorded.
    new_test_ext_with_root(ROOT).execute_with(|| {
        let inputs = TransferPublicInputs {
            merkle_root: ROOT,
            nullifiers: vec![[0xBB; 32], DUMMY, DUMMY, DUMMY],
            output_commitments: vec![[0xDD; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0u8; 32],
        };
        assert_ok!(ShieldedAssets::do_process_transfer_pub(&inputs));
        // Only the real nullifier was recorded.
        assert!(ShieldedAssets::nullifier_exists([0xBB; 32]).is_some());
        assert!(ShieldedAssets::nullifier_exists(DUMMY).is_none());
        assert_eq!(ShieldedAssets::nullifier_count(), 1);
    });
}

#[test]
fn dummy_commitments_are_skipped() {
    new_test_ext_with_root(ROOT).execute_with(|| {
        let inputs = TransferPublicInputs {
            merkle_root: ROOT,
            nullifiers: vec![[0xBB; 32]],
            output_commitments: vec![[0xDD; 32], DUMMY, DUMMY, DUMMY],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0u8; 32],
        };
        assert_ok!(ShieldedAssets::do_process_transfer_pub(&inputs));
        assert_eq!(ShieldedAssets::commitment_count(), 1);
        assert_eq!(ShieldedAssets::commitments(0), Some([0xDD; 32]));
        assert!(ShieldedAssets::commitments(1).is_none());
    });
}

// ── Bounds ────────────────────────────────────────────────────────────────────

#[test]
fn too_many_nullifiers_rejected() {
    new_test_ext_with_root(ROOT).execute_with(|| {
        let inputs = TransferPublicInputs {
            merkle_root: ROOT,
            nullifiers: (1u8..=9).map(|i| [i; 32]).collect(), // 9 non-dummy entries
            output_commitments: vec![[0xDD; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0u8; 32],
        };
        assert_noop!(
            ShieldedAssets::do_process_transfer_pub(&inputs),
            Error::<Test>::TooManyNullifiers,
        );
    });
}

#[test]
fn too_many_commitments_rejected() {
    new_test_ext_with_root(ROOT).execute_with(|| {
        let inputs = TransferPublicInputs {
            merkle_root: ROOT,
            nullifiers: vec![[0xBB; 32]],
            output_commitments: (1u8..=9).map(|i| [i; 32]).collect(), // 9 non-dummy entries
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0u8; 32],
        };
        assert_noop!(
            ShieldedAssets::do_process_transfer_pub(&inputs),
            Error::<Test>::TooManyCommitments,
        );
    });
}

// ── Full sequence ─────────────────────────────────────────────────────────────

#[test]
fn full_transfer_sequence() {
    new_test_ext_with_root(ROOT).execute_with(|| {
        let t1 = TransferPublicInputs {
            merkle_root: ROOT,
            nullifiers: vec![[0x01; 32], [0x02; 32]],
            output_commitments: vec![[0xA1; 32], [0xA2; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        };
        assert_ok!(ShieldedAssets::do_process_transfer_pub(&t1));

        let t2 = TransferPublicInputs {
            merkle_root: ROOT,
            nullifiers: vec![[0x03; 32]],
            output_commitments: vec![[0xB1; 32], [0xB2; 32], [0xB3; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        };
        assert_ok!(ShieldedAssets::do_process_transfer_pub(&t2));

        assert_eq!(ShieldedAssets::commitment_count(), 5);
        assert_eq!(ShieldedAssets::nullifier_count(), 3);
        assert_eq!(ShieldedAssets::transfer_count(), 2);
        assert!(ShieldedAssets::nullifier_exists([0x01; 32]).is_some());
        assert!(ShieldedAssets::nullifier_exists([0x02; 32]).is_some());
        assert!(ShieldedAssets::nullifier_exists([0x03; 32]).is_some());
        assert!(ShieldedAssets::nullifier_exists([0x04; 32]).is_none());
        assert_eq!(ShieldedAssets::commitments(0), Some([0xA1; 32]));
        assert_eq!(ShieldedAssets::commitments(4), Some([0xB3; 32]));

        // Double-spend
        let t3 = TransferPublicInputs {
            merkle_root: ROOT,
            nullifiers: vec![[0x01; 32]],
            output_commitments: vec![[0xC1; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        };
        assert_noop!(
            ShieldedAssets::do_process_transfer_pub(&t3),
            Error::<Test>::NullifierAlreadySpent,
        );
    });
}

// ── shield (deposit) ─────────────────────────────────────────────────────────

/// Happy path: Alice shields 1000 tokens.
/// - Her transparent balance decreases by exactly 1000.
/// - TotalIssuance decreases by exactly 1000 (burn semantics).
/// - CommitmentCount goes from 0 to 1.
/// - The stored commitment is non-zero.
/// - A Shielded event is emitted.
#[test]
fn shield_debits_amount_and_inserts_commitment() {
    new_test_ext_with_balances(vec![(ALICE, INIT_BALANCE)]).execute_with(|| {
        let owner_pubkey = [0xAAu8; 32];
        let blinding = [0xBBu8; 32];
        let amount: Balance = 1_000;

        let issuance_before = pallet_balances::Pallet::<Test>::total_issuance();
        let balance_before = pallet_balances::Pallet::<Test>::free_balance(ALICE);

        assert_ok!(ShieldedAssets::shield(
            RuntimeOrigin::signed(ALICE),
            amount,
            owner_pubkey,
            blinding,
        ));

        // Balance and total issuance decrease by exactly amount.
        assert_eq!(
            pallet_balances::Pallet::<Test>::free_balance(ALICE),
            balance_before - amount,
            "Alice's balance must decrease by the shielded amount",
        );
        assert_eq!(
            pallet_balances::Pallet::<Test>::total_issuance(),
            issuance_before - amount,
            "TotalIssuance must decrease by the shielded amount (burn semantics)",
        );

        // Commitment inserted.
        assert_eq!(ShieldedAssets::commitment_count(), 1);
        let cm = ShieldedAssets::commitments(0).expect("commitment must be at index 0");
        assert_ne!(cm, [0u8; 32], "commitment must not be all-zero");

        // Shielded event emitted.
        System::assert_has_event(Event::<Test>::Shielded { commitment: cm, amount }.into());
    });
}

/// The commitment stored on-chain must match the off-chain Poseidon computation.
/// This proves the pallet and the transfer circuit use the same commitment formula,
/// so shielded notes are spendable by the transfer circuit.
///
/// Formula (both paths): Poseidon_t5(owner_pubkey, amount_u64, NATIVE_ASSET_ID, blinding)
#[test]
fn shield_cm_matches_offchain_poseidon() {
    let owner_pubkey = [0x11u8; 32];
    let blinding = [0x22u8; 32];
    let amount: Balance = 500;

    // Off-chain commitment — same code path as Note::commitment() in the transfer circuit.
    let expected = note_commitment(&owner_pubkey, amount as u64, &NATIVE_ASSET_ID, &blinding);

    new_test_ext_with_balances(vec![(ALICE, INIT_BALANCE)]).execute_with(|| {
        assert_ok!(ShieldedAssets::shield(
            RuntimeOrigin::signed(ALICE),
            amount,
            owner_pubkey,
            blinding,
        ));

        let stored = ShieldedAssets::commitments(0).expect("commitment must exist");
        assert_eq!(
            stored, expected,
            "on-chain commitment must match the transfer circuit's Poseidon_t5 formula",
        );
    });
}

/// Zero amount rejected — zero-value notes are unspendable by the range-check in the circuit.
#[test]
fn shield_zero_amount_rejected() {
    new_test_ext_with_balances(vec![(ALICE, INIT_BALANCE)]).execute_with(|| {
        assert_noop!(
            ShieldedAssets::shield(RuntimeOrigin::signed(ALICE), 0, [0u8; 32], [0u8; 32]),
            Error::<Test>::ZeroAmount,
        );
    });
}

/// Insufficient balance rejected.
#[test]
fn shield_insufficient_balance_rejected() {
    new_test_ext_with_balances(vec![(ALICE, 100)]).execute_with(|| {
        assert_noop!(
            ShieldedAssets::shield(RuntimeOrigin::signed(ALICE), 1_000, [0u8; 32], [1u8; 32]),
            Error::<Test>::InsufficientBalance,
        );
        // Balance must be unchanged.
        assert_eq!(pallet_balances::Pallet::<Test>::free_balance(ALICE), 100);
    });
}

/// MaxCommitments enforced.
#[test]
fn shield_max_commitments_enforced() {
    // Use a tiny MaxCommitments (1) to test the cap without inserting millions.
    // We abuse the existing pallet config (MaxCommitments = 1048576) by
    // pre-filling the counter instead.
    new_test_ext_with_balances(vec![(ALICE, INIT_BALANCE)]).execute_with(|| {
        // Fill the commitment counter to max.
        crate::pallet::CommitmentCount::<Test>::put(1_048_576u64);

        assert_noop!(
            ShieldedAssets::shield(RuntimeOrigin::signed(ALICE), 100, [0u8; 32], [1u8; 32]),
            Error::<Test>::TreeFull,
        );
        // Balance must be unchanged.
        assert_eq!(pallet_balances::Pallet::<Test>::free_balance(ALICE), INIT_BALANCE);
    });
}

/// End-to-end: Alice shields tokens → commitment in tree → Merkle root updated →
/// a transfer referencing that root is accepted by the pallet.
///
/// Note: this test does NOT produce a real Groth16 proof for the shielded note — that
/// requires the prover (see `node/tests/wasm_host_fn.rs`).  It verifies the pallet
/// state machine is consistent: a shield-inserted commitment makes the root valid for
/// subsequent `do_process_transfer` calls.
#[test]
fn shield_end_to_end_commitment_spendable_via_transfer() {
    let owner_pubkey = [0x33u8; 32];
    let blinding = [0x44u8; 32];
    let amount: Balance = 750;

    new_test_ext_with_balances(vec![(ALICE, INIT_BALANCE)]).execute_with(|| {
        // 1. Shield: insert one commitment.
        assert_ok!(ShieldedAssets::shield(
            RuntimeOrigin::signed(ALICE),
            amount,
            owner_pubkey,
            blinding,
        ));
        let cm = ShieldedAssets::commitments(0).unwrap();
        assert_eq!(ShieldedAssets::commitment_count(), 1);

        // 2. Build the single-leaf Merkle tree and derive the root.
        let tree = zc_crypto::merkle::MerkleTree::new(&[cm]);
        let root = tree.root();

        // 3. Submit the new root (simulates off-chain prover output → sudo tx).
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), root));
        assert_eq!(ShieldedAssets::current_merkle_root(), Some(root));

        // 4. A transfer proof that references this root is accepted.
        //    Nullifier and output commitment are placeholders — a real proof would
        //    derive the nullifier from sk and the Merkle path for cm.
        let transfer = TransferPublicInputs {
            merkle_root: root,
            nullifiers: vec![[0xFFu8; 32]],
            output_commitments: vec![[0xEEu8; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0u8; 32],
        };
        assert_ok!(ShieldedAssets::do_process_transfer_pub(&transfer));

        // Final state: 2 commitments (shield + transfer output), 1 nullifier.
        assert_eq!(ShieldedAssets::commitment_count(), 2);
        assert_eq!(ShieldedAssets::nullifier_count(), 1);
    });
}
