use crate::{mock::*, Error, Event};
use frame_support::{assert_noop, assert_ok};
use zk_types::*;

fn dummy_transfer_inputs() -> TransferPublicInputs {
    TransferPublicInputs {
        merkle_root: [0xAA; 32],
        nullifiers: vec![[0xBB; 32], [0xCC; 32]],
        output_commitments: vec![[0xDD; 32], [0xEE; 32]],
        asset_id: NATIVE_ASSET_ID,
        fee_commitment: [0xFF; 32],
    }
}

// -- process_transfer --

#[test]
fn process_transfer_works_without_merkle_root() {
    // First transfer ever, no Merkle root set yet. Should pass
    // because the pallet skips root validation during bootstrap.
    new_test_ext().execute_with(|| {
        let inputs = dummy_transfer_inputs();
        assert_ok!(ShieldedAssets::process_transfer(
            RuntimeOrigin::signed(1),
            inputs,
        ));
        assert_eq!(ShieldedAssets::commitment_count(), 2);
        assert_eq!(ShieldedAssets::nullifier_count(), 2);
        assert_eq!(ShieldedAssets::transfer_count(), 1);
    });
}

#[test]
fn process_transfer_checks_merkle_root() {
    new_test_ext().execute_with(|| {
        // Set a Merkle root first
        let root = [0xAA; 32];
        assert_ok!(ShieldedAssets::update_merkle_root(
            RuntimeOrigin::root(),
            root,
        ));

        // Transfer with matching root should pass
        let mut inputs = dummy_transfer_inputs();
        inputs.merkle_root = root;
        assert_ok!(ShieldedAssets::process_transfer(
            RuntimeOrigin::signed(1),
            inputs,
        ));

        // Transfer with wrong root should fail
        let mut bad_inputs = dummy_transfer_inputs();
        bad_inputs.merkle_root = [0x99; 32];
        bad_inputs.nullifiers = vec![[0x11; 32]]; // different nullifiers so no double-spend
        assert_noop!(
            ShieldedAssets::process_transfer(RuntimeOrigin::signed(1), bad_inputs),
            Error::<Test>::InvalidMerkleRoot,
        );
    });
}

#[test]
fn process_transfer_rejects_double_spend() {
    new_test_ext().execute_with(|| {
        let inputs = dummy_transfer_inputs();

        // First time should work
        assert_ok!(ShieldedAssets::process_transfer(
            RuntimeOrigin::signed(1),
            inputs.clone(),
        ));

        // Same nullifiers again should fail
        assert_noop!(
            ShieldedAssets::process_transfer(RuntimeOrigin::signed(1), inputs),
            Error::<Test>::NullifierAlreadySpent,
        );
    });
}

#[test]
fn process_transfer_appends_commitments() {
    new_test_ext().execute_with(|| {
        let inputs = dummy_transfer_inputs();
        assert_ok!(ShieldedAssets::process_transfer(
            RuntimeOrigin::signed(1),
            inputs.clone(),
        ));

        // Two commitments should be stored at index 0 and 1
        assert_eq!(ShieldedAssets::commitments(0), Some([0xDD; 32]));
        assert_eq!(ShieldedAssets::commitments(1), Some([0xEE; 32]));
        assert_eq!(ShieldedAssets::commitment_count(), 2);

        // Do another transfer with different nullifiers
        let inputs2 = TransferPublicInputs {
            merkle_root: [0xAA; 32],
            nullifiers: vec![[0x11; 32]],
            output_commitments: vec![[0x22; 32], [0x33; 32], [0x44; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        };
        assert_ok!(ShieldedAssets::process_transfer(
            RuntimeOrigin::signed(1),
            inputs2,
        ));

        // Commitments at index 2, 3, 4
        assert_eq!(ShieldedAssets::commitments(2), Some([0x22; 32]));
        assert_eq!(ShieldedAssets::commitments(3), Some([0x33; 32]));
        assert_eq!(ShieldedAssets::commitments(4), Some([0x44; 32]));
        assert_eq!(ShieldedAssets::commitment_count(), 5);
    });
}

#[test]
fn process_transfer_marks_nullifiers_spent() {
    new_test_ext().execute_with(|| {
        let inputs = dummy_transfer_inputs();
        assert_ok!(ShieldedAssets::process_transfer(
            RuntimeOrigin::signed(1),
            inputs,
        ));

        // Both nullifiers should exist in the set
        assert!(ShieldedAssets::nullifier_exists([0xBB; 32]).is_some());
        assert!(ShieldedAssets::nullifier_exists([0xCC; 32]).is_some());

        // An unspent nullifier should not exist
        assert!(ShieldedAssets::nullifier_exists([0x99; 32]).is_none());
    });
}

#[test]
fn process_transfer_rejects_too_many_nullifiers() {
    new_test_ext().execute_with(|| {
        let inputs = TransferPublicInputs {
            merkle_root: [0xAA; 32],
            nullifiers: vec![[0xBB; 32]; 9], // 9 exceeds MAX_INPUTS (8)
            output_commitments: vec![[0xDD; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        };
        assert_noop!(
            ShieldedAssets::process_transfer(RuntimeOrigin::signed(1), inputs),
            Error::<Test>::TooManyNullifiers,
        );
    });
}

#[test]
fn process_transfer_rejects_too_many_commitments() {
    new_test_ext().execute_with(|| {
        let inputs = TransferPublicInputs {
            merkle_root: [0xAA; 32],
            nullifiers: vec![[0xBB; 32]],
            output_commitments: vec![[0xDD; 32]; 9], // 9 exceeds MAX_OUTPUTS (8)
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        };
        assert_noop!(
            ShieldedAssets::process_transfer(RuntimeOrigin::signed(1), inputs),
            Error::<Test>::TooManyCommitments,
        );
    });
}

#[test]
fn process_transfer_emits_event() {
    new_test_ext().execute_with(|| {
        let inputs = dummy_transfer_inputs();
        assert_ok!(ShieldedAssets::process_transfer(
            RuntimeOrigin::signed(1),
            inputs,
        ));
        System::assert_last_event(
            Event::<Test>::ShieldedTransferProcessed {
                nullifiers_added: 2,
                commitments_added: 2,
                asset_id: NATIVE_ASSET_ID,
            }
            .into(),
        );
    });
}

// -- update_merkle_root --

#[test]
fn update_merkle_root_works() {
    new_test_ext().execute_with(|| {
        let root = [0xAB; 32];
        assert_ok!(ShieldedAssets::update_merkle_root(
            RuntimeOrigin::root(),
            root,
        ));
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

        // Current root is root3
        assert_eq!(ShieldedAssets::current_merkle_root(), Some(root3));

        // But root1 and root2 should still be valid for proof verification
        // (a prover might have generated proof against an older root)
        let mut inputs1 = dummy_transfer_inputs();
        inputs1.merkle_root = root1;
        inputs1.nullifiers = vec![[0x10; 32]];
        assert_ok!(ShieldedAssets::process_transfer(RuntimeOrigin::signed(1), inputs1));

        let mut inputs2 = dummy_transfer_inputs();
        inputs2.merkle_root = root2;
        inputs2.nullifiers = vec![[0x20; 32]];
        assert_ok!(ShieldedAssets::process_transfer(RuntimeOrigin::signed(1), inputs2));
    });
}

#[test]
fn update_merkle_root_emits_event() {
    new_test_ext().execute_with(|| {
        let root = [0xAB; 32];
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), root));
        System::assert_last_event(
            Event::<Test>::MerkleRootUpdated { root }.into(),
        );
    });
}

// -- Multi-transfer sequence --

#[test]
fn full_transfer_sequence() {
    new_test_ext().execute_with(|| {
        // Set initial Merkle root
        let root = [0xAA; 32];
        assert_ok!(ShieldedAssets::update_merkle_root(RuntimeOrigin::root(), root));

        // Transfer 1: spend 2 notes, create 2 notes
        let t1 = TransferPublicInputs {
            merkle_root: root,
            nullifiers: vec![[0x01; 32], [0x02; 32]],
            output_commitments: vec![[0xA1; 32], [0xA2; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        };
        assert_ok!(ShieldedAssets::process_transfer(RuntimeOrigin::signed(1), t1));

        // Transfer 2: spend 1 note, create 3 notes
        let t2 = TransferPublicInputs {
            merkle_root: root,
            nullifiers: vec![[0x03; 32]],
            output_commitments: vec![[0xB1; 32], [0xB2; 32], [0xB3; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        };
        assert_ok!(ShieldedAssets::process_transfer(RuntimeOrigin::signed(2), t2));

        // Verify final state
        assert_eq!(ShieldedAssets::commitment_count(), 5);
        assert_eq!(ShieldedAssets::nullifier_count(), 3);
        assert_eq!(ShieldedAssets::transfer_count(), 2);

        // Verify nullifiers are tracked
        assert!(ShieldedAssets::nullifier_exists([0x01; 32]).is_some());
        assert!(ShieldedAssets::nullifier_exists([0x02; 32]).is_some());
        assert!(ShieldedAssets::nullifier_exists([0x03; 32]).is_some());
        assert!(ShieldedAssets::nullifier_exists([0x04; 32]).is_none());

        // Verify commitments are stored in order
        assert_eq!(ShieldedAssets::commitments(0), Some([0xA1; 32]));
        assert_eq!(ShieldedAssets::commitments(1), Some([0xA2; 32]));
        assert_eq!(ShieldedAssets::commitments(2), Some([0xB1; 32]));
        assert_eq!(ShieldedAssets::commitments(3), Some([0xB2; 32]));
        assert_eq!(ShieldedAssets::commitments(4), Some([0xB3; 32]));

        // Double-spend attempt on note from transfer 1
        let t3 = TransferPublicInputs {
            merkle_root: root,
            nullifiers: vec![[0x01; 32]], // already spent
            output_commitments: vec![[0xC1; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        };
        assert_noop!(
            ShieldedAssets::process_transfer(RuntimeOrigin::signed(3), t3),
            Error::<Test>::NullifierAlreadySpent,
        );
    });
}
