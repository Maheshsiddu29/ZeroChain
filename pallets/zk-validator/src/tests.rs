use crate::{mock::*, Error, Event};
use frame_support::{assert_noop, assert_ok};
use zk_types::*;

#[test]
fn register_validator_works() {
    new_test_ext().execute_with(|| {
        let commitment = [0xAA; 32];
        assert_ok!(ZkValidator::register_validator(RuntimeOrigin::root(), commitment));
        assert_eq!(ZkValidator::validator_count(), 1);
        assert_eq!(ZkValidator::validator_commitment(0), Some(commitment));
        System::assert_last_event(
            Event::<Test>::ValidatorRegistered { index: 0, commitment }.into(),
        );
    });
}

#[test]
fn register_multiple_validators() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkValidator::register_validator(RuntimeOrigin::root(), [0x01; 32]));
        assert_ok!(ZkValidator::register_validator(RuntimeOrigin::root(), [0x02; 32]));
        assert_ok!(ZkValidator::register_validator(RuntimeOrigin::root(), [0x03; 32]));
        assert_eq!(ZkValidator::validator_count(), 3);
    });
}

#[test]
fn register_rejects_non_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ZkValidator::register_validator(RuntimeOrigin::signed(1), [0xAA; 32]),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

#[test]
fn register_rejects_duplicate_commitment() {
    new_test_ext().execute_with(|| {
        let commitment = [0xAA; 32];
        assert_ok!(ZkValidator::register_validator(RuntimeOrigin::root(), commitment));
        assert_noop!(
            ZkValidator::register_validator(RuntimeOrigin::root(), commitment),
            Error::<Test>::CommitmentAlreadyRegistered,
        );
    });
}

#[test]
fn register_increments_count() {
    new_test_ext().execute_with(|| {
        for i in 0..10u8 {
            let mut commitment = [0u8; 32];
            commitment[0] = i;
            assert_ok!(ZkValidator::register_validator(RuntimeOrigin::root(), commitment));
        }
        assert_eq!(ZkValidator::validator_count(), 10);
    });
}

#[test]
fn update_root_works() {
    new_test_ext().execute_with(|| {
        let root = [0xBB; 32];
        assert_ok!(ZkValidator::update_validator_root(RuntimeOrigin::root(), root));
        assert_eq!(ZkValidator::validator_root(), Some(root));
    });
}

#[test]
fn update_root_rejects_non_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ZkValidator::update_validator_root(RuntimeOrigin::signed(1), [0xBB; 32]),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

#[test]
fn advance_epoch_works() {
    new_test_ext().execute_with(|| {
        assert_eq!(ZkValidator::current_epoch(), 0);
        assert_ok!(ZkValidator::advance_epoch(RuntimeOrigin::root()));
        assert_eq!(ZkValidator::current_epoch(), 1);
    });
}

#[test]
fn advance_epoch_resets_proof_counter() {
    new_test_ext().execute_with(|| {
        let root = [0xBB; 32];
        assert_ok!(ZkValidator::update_validator_root(RuntimeOrigin::root(), root));

        let inputs = MembershipPublicInputs { validator_root: root, epoch: 0, slot: 1 };
        assert_ok!(crate::pallet::Pallet::<Test>::process_verified_membership(&inputs));
        assert_eq!(ZkValidator::proofs_this_epoch(), 1);

        assert_ok!(ZkValidator::advance_epoch(RuntimeOrigin::root()));
        assert_eq!(ZkValidator::proofs_this_epoch(), 0);
    });
}

#[test]
fn process_membership_works() {
    new_test_ext().execute_with(|| {
        let root = [0xCC; 32];
        assert_ok!(ZkValidator::update_validator_root(RuntimeOrigin::root(), root));

        let inputs = MembershipPublicInputs { validator_root: root, epoch: 0, slot: 5 };
        assert_ok!(crate::pallet::Pallet::<Test>::process_verified_membership(&inputs));
        assert_eq!(ZkValidator::proofs_this_epoch(), 1);
    });
}

#[test]
fn process_membership_rejects_wrong_epoch() {
    new_test_ext().execute_with(|| {
        let root = [0xCC; 32];
        assert_ok!(ZkValidator::update_validator_root(RuntimeOrigin::root(), root));

        let inputs = MembershipPublicInputs { validator_root: root, epoch: 99, slot: 5 };
        assert_noop!(
            crate::pallet::Pallet::<Test>::process_verified_membership(&inputs),
            Error::<Test>::EpochMismatch,
        );
    });
}

#[test]
fn process_membership_rejects_wrong_root() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkValidator::update_validator_root(RuntimeOrigin::root(), [0xCC; 32]));

        let inputs = MembershipPublicInputs { validator_root: [0xDD; 32], epoch: 0, slot: 5 };
        assert_noop!(
            crate::pallet::Pallet::<Test>::process_verified_membership(&inputs),
            Error::<Test>::ValidatorRootMismatch,
        );
    });
}

#[test]
fn process_membership_fails_without_root() {
    new_test_ext().execute_with(|| {
        let inputs = MembershipPublicInputs { validator_root: [0xCC; 32], epoch: 0, slot: 5 };
        assert_noop!(
            crate::pallet::Pallet::<Test>::process_verified_membership(&inputs),
            Error::<Test>::NoValidatorRoot,
        );
    });
}

#[test]
fn slash_validator_works() {
    new_test_ext().execute_with(|| {
        let nullifier = [0xDD; 32];
        assert_ok!(ZkValidator::slash_validator(RuntimeOrigin::root(), nullifier));
        assert!(ZkValidator::is_slashed(nullifier).is_some());
        assert_eq!(ZkValidator::slashed_count(), 1);
    });
}

#[test]
fn slash_rejects_duplicate() {
    new_test_ext().execute_with(|| {
        let nullifier = [0xDD; 32];
        assert_ok!(ZkValidator::slash_validator(RuntimeOrigin::root(), nullifier));
        assert_noop!(
            ZkValidator::slash_validator(RuntimeOrigin::root(), nullifier),
            Error::<Test>::AlreadySlashed,
        );
    });
}

#[test]
fn slash_rejects_non_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ZkValidator::slash_validator(RuntimeOrigin::signed(1), [0xDD; 32]),
            sp_runtime::DispatchError::BadOrigin,
        );
    });
}

#[test]
fn full_validator_lifecycle() {
    new_test_ext().execute_with(|| {
        // register 3 validators
        assert_ok!(ZkValidator::register_validator(RuntimeOrigin::root(), [0x01; 32]));
        assert_ok!(ZkValidator::register_validator(RuntimeOrigin::root(), [0x02; 32]));
        assert_ok!(ZkValidator::register_validator(RuntimeOrigin::root(), [0x03; 32]));
        assert_eq!(ZkValidator::validator_count(), 3);

        // set root (computed off-chain for prototype)
        let root = [0xAB; 32];
        assert_ok!(ZkValidator::update_validator_root(RuntimeOrigin::root(), root));

        // two validators prove membership
        let inputs1 = MembershipPublicInputs { validator_root: root, epoch: 0, slot: 1 };
        let inputs2 = MembershipPublicInputs { validator_root: root, epoch: 0, slot: 2 };
        assert_ok!(crate::pallet::Pallet::<Test>::process_verified_membership(&inputs1));
        assert_ok!(crate::pallet::Pallet::<Test>::process_verified_membership(&inputs2));
        assert_eq!(ZkValidator::proofs_this_epoch(), 2);

        // advance epoch
        assert_ok!(ZkValidator::advance_epoch(RuntimeOrigin::root()));
        assert_eq!(ZkValidator::current_epoch(), 1);
        assert_eq!(ZkValidator::proofs_this_epoch(), 0);

        // old epoch proofs rejected
        let stale = MembershipPublicInputs { validator_root: root, epoch: 0, slot: 3 };
        assert_noop!(
            crate::pallet::Pallet::<Test>::process_verified_membership(&stale),
            Error::<Test>::EpochMismatch,
        );

        // slash a validator
        assert_ok!(ZkValidator::slash_validator(RuntimeOrigin::root(), [0xFF; 32]));
        assert_eq!(ZkValidator::slashed_count(), 1);
    });
}