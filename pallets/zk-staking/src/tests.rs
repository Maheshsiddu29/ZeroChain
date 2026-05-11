//! Tests for pallet-zk-staking

use crate::{mock::*, Error, Event};
use frame_support::{assert_ok, assert_noop};

#[test]
fn test_stake_validator() {
    new_test_ext().execute_with(|| {
        let commitment = [1u8; 32];
        let amount = 5000u128;

        assert_ok!(ZkStaking::stake(
            RuntimeOrigin::signed(1),
            commitment,
            amount,
        ));

        assert!(ZkStaking::is_validator(&commitment));
        assert_eq!(ZkStaking::total_staked(), amount);
        assert_eq!(ZkStaking::validator_count(), 1);

        // Check event
        System::assert_last_event(
            Event::ValidatorStaked { commitment, amount }.into()
        );
    });
}

#[test]
fn test_stake_below_minimum_rejected() {
    new_test_ext().execute_with(|| {
        let commitment = [1u8; 32];
        let amount = 100u128; // Below MinStakeAmount (1000)

        assert_noop!(
            ZkStaking::stake(RuntimeOrigin::signed(1), commitment, amount),
            Error::<Test>::StakeBelowMinimum
        );
    });
}

#[test]
fn test_duplicate_commitment_rejected() {
    new_test_ext().execute_with(|| {
        let commitment = [1u8; 32];
        let amount = 5000u128;

        assert_ok!(ZkStaking::stake(
            RuntimeOrigin::signed(1),
            commitment,
            amount,
        ));

        // Try to stake same commitment again
        assert_noop!(
            ZkStaking::stake(RuntimeOrigin::signed(2), commitment, amount),
            Error::<Test>::CommitmentAlreadyStaked
        );
    });
}

#[test]
fn test_unstake_validator() {
    new_test_ext().execute_with(|| {
        let commitment = [1u8; 32];
        let amount = 5000u128;
        let nullifier = [2u8; 32];

        // Stake
        assert_ok!(ZkStaking::stake(
            RuntimeOrigin::signed(1),
            commitment,
            amount,
        ));

        assert_eq!(ZkStaking::validator_count(), 1);

        // Unstake
        assert_ok!(ZkStaking::unstake(
            RuntimeOrigin::signed(1),
            commitment,
            vec![1, 2, 3], // Dummy proof
            nullifier,
        ));

        assert_eq!(ZkStaking::validator_count(), 0);
        assert_eq!(ZkStaking::total_staked(), 0);
        assert!(!ZkStaking::is_validator(&commitment));
    });
}

#[test]
fn test_multiple_validators() {
    new_test_ext().execute_with(|| {
        for i in 0..10 {
            let commitment = [i as u8; 32];
            let amount = 5000u128;

            assert_ok!(ZkStaking::stake(
                RuntimeOrigin::signed(i as u64),
                commitment,
                amount,
            ));
        }

        assert_eq!(ZkStaking::validator_count(), 10);
        assert_eq!(ZkStaking::total_staked(), 50000);
    });
}

#[test]
fn test_slash_validator() {
    new_test_ext().execute_with(|| {
        let nullifier = [1u8; 32];
        let fraud_proof = vec![1, 2, 3, 4, 5];

        assert_ok!(ZkStaking::slash(
            RuntimeOrigin::signed(1),
            fraud_proof,
            nullifier,
        ));

        // Nullifier should be marked as used
        assert!(ZkStaking::slashed_nullifiers(&nullifier));
    });
}

#[test]
fn test_double_slash_prevented() {
    new_test_ext().execute_with(|| {
        let nullifier = [1u8; 32];
        let fraud_proof = vec![1, 2, 3, 4, 5];

        // First slash succeeds
        assert_ok!(ZkStaking::slash(
            RuntimeOrigin::signed(1),
            fraud_proof.clone(),
            nullifier,
        ));

        // Second slash with same nullifier fails
        assert_noop!(
            ZkStaking::slash(RuntimeOrigin::signed(2), fraud_proof, nullifier),
            Error::<Test>::NullifierAlreadySlashed
        );
    });
}

#[test]
fn test_epoch_transition() {
    new_test_ext().execute_with(|| {
        assert_eq!(ZkStaking::current_epoch(), 0);

        assert_ok!(ZkStaking::transition_epoch(RuntimeOrigin::root()));

        assert_eq!(ZkStaking::current_epoch(), 1);
    });
}

#[test]
fn test_validator_root_computation() {
    new_test_ext().execute_with(|| {
        let commitment = [1u8; 32];
        let amount = 5000u128;

        assert_ok!(ZkStaking::stake(
            RuntimeOrigin::signed(1),
            commitment,
            amount,
        ));

        let root = ZkStaking::validator_root();
        assert_ne!(root, [0u8; 32]); // Should compute non-zero root
    });
}