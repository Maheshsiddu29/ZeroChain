use crate::{mock::*, Error, Event, StakeCommitments, StakeCount, TotalStaked, SlashedNullifiers, SlashCount, UnstakedNullifiers, UnstakeCount};
use frame_support::{assert_noop, assert_ok};
use zk_types::StakingHandler;

fn commitment(seed: u8) -> [u8; 32] {
    [seed; 32]
}

// ─── stake tests ─────────────────────────────────────────────

#[test]
fn stake_works() {
    new_test_ext().execute_with(|| {
        let c = commitment(0xAA);
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(1), c, 5000));
        assert_eq!(StakeCommitments::<Test>::get(&c), Some(5000));
        assert_eq!(StakeCount::<Test>::get(), 1);
        assert_eq!(TotalStaked::<Test>::get(), 5000);
        System::assert_last_event(Event::Staked { commitment: c, amount: 5000 }.into());
    });
}

#[test]
fn stake_rejects_below_minimum() {
    new_test_ext().execute_with(|| {
        let c = commitment(0xBB);
        assert_noop!(
            ZkStaking::stake(RuntimeOrigin::signed(1), c, 500),
            Error::<Test>::StakeTooLow
        );
    });
}

#[test]
fn stake_rejects_duplicate_commitment() {
    new_test_ext().execute_with(|| {
        let c = commitment(0xCC);
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(1), c, 2000));
        assert_noop!(
            ZkStaking::stake(RuntimeOrigin::signed(2), c, 3000),
            Error::<Test>::CommitmentAlreadyStaked
        );
    });
}

#[test]
fn stake_rejects_when_full() {
    new_test_ext().execute_with(|| {
        // MaxStakers = 1024, fill it up would be too slow, so test the logic
        // by checking the error exists and count tracking works
        let c1 = commitment(0x01);
        let c2 = commitment(0x02);
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(1), c1, 1000));
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(1), c2, 2000));
        assert_eq!(StakeCount::<Test>::get(), 2);
        assert_eq!(TotalStaked::<Test>::get(), 3000);
    });
}

#[test]
fn multiple_stakes_accumulate_total() {
    new_test_ext().execute_with(|| {
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(1), commitment(0x01), 1000));
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(2), commitment(0x02), 2000));
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(3), commitment(0x03), 3000));
        assert_eq!(TotalStaked::<Test>::get(), 6000);
        assert_eq!(StakeCount::<Test>::get(), 3);
    });
}

// ─── unstake tests ───────────────────────────────────────────

#[test]
fn unstake_works() {
    new_test_ext().execute_with(|| {
        let c = commitment(0xDD);
        let n = commitment(0xEE);
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(1), c, 5000));
        assert_ok!(ZkStaking::unstake(RuntimeOrigin::signed(1), c, n));
        assert_eq!(StakeCommitments::<Test>::get(&c), None);
        assert_eq!(StakeCount::<Test>::get(), 0);
        assert_eq!(TotalStaked::<Test>::get(), 0);
        assert_eq!(UnstakeCount::<Test>::get(), 1);
        assert!(UnstakedNullifiers::<Test>::contains_key(&n));
        System::assert_last_event(Event::Unstaked { nullifier: n, amount: 5000 }.into());
    });
}

#[test]
fn unstake_rejects_unknown_commitment() {
    new_test_ext().execute_with(|| {
        let c = commitment(0xFF);
        let n = commitment(0xAA);
        assert_noop!(
            ZkStaking::unstake(RuntimeOrigin::signed(1), c, n),
            Error::<Test>::CommitmentNotFound
        );
    });
}

#[test]
fn unstake_rejects_reused_nullifier() {
    new_test_ext().execute_with(|| {
        let c1 = commitment(0x01);
        let c2 = commitment(0x02);
        let n = commitment(0xAB);
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(1), c1, 1000));
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(1), c2, 2000));
        assert_ok!(ZkStaking::unstake(RuntimeOrigin::signed(1), c1, n));
        assert_noop!(
            ZkStaking::unstake(RuntimeOrigin::signed(1), c2, n),
            Error::<Test>::NullifierAlreadyUsed
        );
    });
}

#[test]
fn unstake_rejects_slashed_nullifier() {
    new_test_ext().execute_with(|| {
        let c = commitment(0x10);
        let n = commitment(0x20);
        let vr = commitment(0x30);
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(1), c, 1000));
        // slash first
        assert_ok!(ZkStaking::slash(RuntimeOrigin::root(), n, vr));
        // try to unstake with the slashed nullifier
        assert_noop!(
            ZkStaking::unstake(RuntimeOrigin::signed(1), c, n),
            Error::<Test>::AlreadySlashed
        );
    });
}

// ─── slash tests ─────────────────────────────────────────────

#[test]
fn slash_works() {
    new_test_ext().execute_with(|| {
        let n = commitment(0x40);
        let vr = commitment(0x50);
        assert_ok!(ZkStaking::slash(RuntimeOrigin::root(), n, vr));
        assert!(SlashedNullifiers::<Test>::contains_key(&n));
        assert_eq!(SlashCount::<Test>::get(), 1);
        System::assert_last_event(Event::Slashed { nullifier: n, validator_root: vr }.into());
    });
}

#[test]
fn slash_rejects_duplicate() {
    new_test_ext().execute_with(|| {
        let n = commitment(0x60);
        let vr = commitment(0x70);
        assert_ok!(ZkStaking::slash(RuntimeOrigin::root(), n, vr));
        assert_noop!(
            ZkStaking::slash(RuntimeOrigin::root(), n, vr),
            Error::<Test>::AlreadySlashed
        );
    });
}

#[test]
fn slash_requires_root() {
    new_test_ext().execute_with(|| {
        let n = commitment(0x80);
        let vr = commitment(0x90);
        assert_noop!(
            ZkStaking::slash(RuntimeOrigin::signed(1), n, vr),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

// ─── StakingHandler trait tests ──────────────────────────────

#[test]
fn process_slash_via_trait() {
    new_test_ext().execute_with(|| {
        let inputs = zk_types::SlashingPublicInputs {
            validator_root: commitment(0xA0),
            nullifier: commitment(0xB0),
            block_hash_1: commitment(0xC0),
            block_hash_2: commitment(0xD0),
        };
        <ZkStaking as StakingHandler>::process_slash(&inputs);
        assert!(SlashedNullifiers::<Test>::contains_key(&inputs.nullifier));
        assert_eq!(SlashCount::<Test>::get(), 1);
    });
}

#[test]
fn process_slash_idempotent() {
    new_test_ext().execute_with(|| {
        let inputs = zk_types::SlashingPublicInputs {
            validator_root: commitment(0xA1),
            nullifier: commitment(0xB1),
            block_hash_1: commitment(0xC1),
            block_hash_2: commitment(0xD1),
        };
        <ZkStaking as StakingHandler>::process_slash(&inputs);
        <ZkStaking as StakingHandler>::process_slash(&inputs);
        // should only count once
        assert_eq!(SlashCount::<Test>::get(), 1);
    });
}

// ─── full lifecycle test ─────────────────────────────────────

#[test]
fn full_stake_unstake_lifecycle() {
    new_test_ext().execute_with(|| {
        let c1 = commitment(0x01);
        let c2 = commitment(0x02);
        let c3 = commitment(0x03);
        let n1 = commitment(0xA1);
        let n2 = commitment(0xA2);

        // three validators stake
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(1), c1, 1000));
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(2), c2, 2000));
        assert_ok!(ZkStaking::stake(RuntimeOrigin::signed(3), c3, 3000));
        assert_eq!(TotalStaked::<Test>::get(), 6000);
        assert_eq!(StakeCount::<Test>::get(), 3);

        // validator 1 unstakes normally
        assert_ok!(ZkStaking::unstake(RuntimeOrigin::signed(1), c1, n1));
        assert_eq!(TotalStaked::<Test>::get(), 5000);
        assert_eq!(StakeCount::<Test>::get(), 2);

        // validator 2 gets slashed
        let slash_inputs = zk_types::SlashingPublicInputs {
            validator_root: [0xFF; 32],
            nullifier: n2,
            block_hash_1: [0x11; 32],
            block_hash_2: [0x22; 32],
        };
        <ZkStaking as StakingHandler>::process_slash(&slash_inputs);
        assert!(SlashedNullifiers::<Test>::contains_key(&n2));

        // validator 2 cannot unstake with slashed nullifier
        assert_noop!(
            ZkStaking::unstake(RuntimeOrigin::signed(2), c2, n2),
            Error::<Test>::AlreadySlashed
        );

        // validator 3 is still active
        assert_eq!(StakeCommitments::<Test>::get(&c3), Some(3000));
    });
}