use crate::{mock::*, Error, Event, AggregatePublicKey, Threshold, TotalSigners, PartialSignatures, SigCount, FinalizedBlocks, FinalizedCount};
use frame_support::{assert_noop, assert_ok};

fn block_hash(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn fake_key() -> Vec<u8> {
    vec![0xAA; 48] // BLS12-381 compressed pubkey size
}

fn fake_sig(seed: u8) -> Vec<u8> {
    vec![seed; 96] // BLS12-381 compressed sig size
}

fn setup_threshold(t: u32, n: u32) {
    assert_ok!(BlsConsensus::set_aggregate_key(RuntimeOrigin::root(), fake_key()));
    assert_ok!(BlsConsensus::set_threshold(RuntimeOrigin::root(), t, n));
}

// ─── set_aggregate_key tests ─────────────────────────────────

#[test]
fn set_aggregate_key_works() {
    new_test_ext().execute_with(|| {
        let key = fake_key();
        assert_ok!(BlsConsensus::set_aggregate_key(RuntimeOrigin::root(), key.clone()));
        assert!(AggregatePublicKey::<Test>::get().is_some());
        assert_eq!(AggregatePublicKey::<Test>::get().unwrap().len(), 48);
        System::assert_last_event(Event::AggregateKeySet { key_size: 48 }.into());
    });
}

#[test]
fn set_aggregate_key_requires_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            BlsConsensus::set_aggregate_key(RuntimeOrigin::signed(1), fake_key()),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn set_aggregate_key_rejects_oversized() {
    new_test_ext().execute_with(|| {
        let big_key = vec![0xFF; 300]; // exceeds MaxKeySize=256
        assert_noop!(
            BlsConsensus::set_aggregate_key(RuntimeOrigin::root(), big_key),
            Error::<Test>::KeyTooLarge
        );
    });
}

// ─── set_threshold tests ─────────────────────────────────────

#[test]
fn set_threshold_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(BlsConsensus::set_threshold(RuntimeOrigin::root(), 2, 3));
        assert_eq!(Threshold::<Test>::get(), 2);
        assert_eq!(TotalSigners::<Test>::get(), 3);
        System::assert_last_event(Event::ThresholdUpdated { threshold: 2, total_signers: 3 }.into());
    });
}

#[test]
fn set_threshold_rejects_zero() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            BlsConsensus::set_threshold(RuntimeOrigin::root(), 0, 3),
            Error::<Test>::InvalidThreshold
        );
    });
}

#[test]
fn set_threshold_rejects_t_greater_than_n() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            BlsConsensus::set_threshold(RuntimeOrigin::root(), 5, 3),
            Error::<Test>::InvalidThreshold
        );
    });
}

#[test]
fn set_threshold_requires_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            BlsConsensus::set_threshold(RuntimeOrigin::signed(1), 2, 3),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

// ─── submit_partial_sig tests ────────────────────────────────

#[test]
fn submit_partial_sig_works() {
    new_test_ext().execute_with(|| {
        setup_threshold(2, 3);
        let bh = block_hash(0x01);
        assert_ok!(BlsConsensus::submit_partial_sig(
            RuntimeOrigin::signed(1), bh, 0, fake_sig(0xA1)
        ));
        assert_eq!(SigCount::<Test>::get(&bh), 1);
        System::assert_last_event(Event::PartialSigSubmitted {
            block_hash: bh, signer_index: 0, sig_count: 1
        }.into());
    });
}

#[test]
fn submit_partial_sig_rejects_without_key() {
    new_test_ext().execute_with(|| {
        assert_ok!(BlsConsensus::set_threshold(RuntimeOrigin::root(), 2, 3));
        let bh = block_hash(0x02);
        assert_noop!(
            BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(1), bh, 0, fake_sig(0xA2)),
            Error::<Test>::NoAggregateKey
        );
    });
}

#[test]
fn submit_partial_sig_rejects_invalid_index() {
    new_test_ext().execute_with(|| {
        setup_threshold(2, 3);
        let bh = block_hash(0x03);
        assert_noop!(
            BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(1), bh, 5, fake_sig(0xA3)),
            Error::<Test>::InvalidSignerIndex
        );
    });
}

#[test]
fn submit_partial_sig_rejects_duplicate() {
    new_test_ext().execute_with(|| {
        setup_threshold(2, 3);
        let bh = block_hash(0x04);
        assert_ok!(BlsConsensus::submit_partial_sig(
            RuntimeOrigin::signed(1), bh, 0, fake_sig(0xA4)
        ));
        assert_noop!(
            BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(1), bh, 0, fake_sig(0xB4)),
            Error::<Test>::DuplicateSignature
        );
    });
}

#[test]
fn submit_partial_sig_rejects_after_finalized() {
    new_test_ext().execute_with(|| {
        setup_threshold(2, 3);
        let bh = block_hash(0x05);
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(1), bh, 0, fake_sig(0xA5)));
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(2), bh, 1, fake_sig(0xB5)));
        assert_ok!(BlsConsensus::finalize_block(RuntimeOrigin::root(), bh, fake_sig(0xFF)));
        assert_noop!(
            BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(3), bh, 2, fake_sig(0xC5)),
            Error::<Test>::AlreadyFinalized
        );
    });
}

#[test]
fn threshold_reached_event_emitted() {
    new_test_ext().execute_with(|| {
        setup_threshold(2, 3);
        let bh = block_hash(0x06);
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(1), bh, 0, fake_sig(0xA6)));
        // first sig: no threshold event
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(2), bh, 1, fake_sig(0xB6)));
        // second sig: threshold reached
        System::assert_last_event(Event::ThresholdReached {
            block_hash: bh, sig_count: 2, threshold: 2
        }.into());
    });
}

// ─── finalize_block tests ────────────────────────────────────

#[test]
fn finalize_block_works() {
    new_test_ext().execute_with(|| {
        setup_threshold(2, 3);
        let bh = block_hash(0x07);
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(1), bh, 0, fake_sig(0xA7)));
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(2), bh, 1, fake_sig(0xB7)));
        assert_ok!(BlsConsensus::finalize_block(RuntimeOrigin::root(), bh, fake_sig(0xFF)));
        assert!(FinalizedBlocks::<Test>::contains_key(&bh));
        assert_eq!(FinalizedCount::<Test>::get(), 1);
        System::assert_last_event(Event::BlockFinalized { block_hash: bh, sig_count: 2 }.into());
    });
}

#[test]
fn finalize_block_rejects_below_threshold() {
    new_test_ext().execute_with(|| {
        setup_threshold(2, 3);
        let bh = block_hash(0x08);
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(1), bh, 0, fake_sig(0xA8)));
        // only 1 sig, need 2
        assert_noop!(
            BlsConsensus::finalize_block(RuntimeOrigin::root(), bh, fake_sig(0xFF)),
            Error::<Test>::ThresholdNotMet
        );
    });
}

#[test]
fn finalize_block_rejects_duplicate() {
    new_test_ext().execute_with(|| {
        setup_threshold(2, 3);
        let bh = block_hash(0x09);
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(1), bh, 0, fake_sig(0xA9)));
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(2), bh, 1, fake_sig(0xB9)));
        assert_ok!(BlsConsensus::finalize_block(RuntimeOrigin::root(), bh, fake_sig(0xFF)));
        assert_noop!(
            BlsConsensus::finalize_block(RuntimeOrigin::root(), bh, fake_sig(0xFF)),
            Error::<Test>::AlreadyFinalized
        );
    });
}

#[test]
fn finalize_block_requires_root() {
    new_test_ext().execute_with(|| {
        setup_threshold(2, 3);
        let bh = block_hash(0x0A);
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(1), bh, 0, fake_sig(0xAA)));
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(2), bh, 1, fake_sig(0xBA)));
        assert_noop!(
            BlsConsensus::finalize_block(RuntimeOrigin::signed(1), bh, fake_sig(0xFF)),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

// ─── full lifecycle test ─────────────────────────────────────

#[test]
fn full_2_of_3_threshold_lifecycle() {
    new_test_ext().execute_with(|| {
        // setup 2-of-3 threshold
        setup_threshold(2, 3);

        // block 1: all three validators submit, finalize
        let b1 = block_hash(0x10);
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(1), b1, 0, fake_sig(0x01)));
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(2), b1, 1, fake_sig(0x02)));
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(3), b1, 2, fake_sig(0x03)));
        assert_eq!(SigCount::<Test>::get(&b1), 3);
        assert_ok!(BlsConsensus::finalize_block(RuntimeOrigin::root(), b1, fake_sig(0xF1)));
        assert_eq!(FinalizedCount::<Test>::get(), 1);

        // block 2: only two validators submit (minimum threshold), finalize
        let b2 = block_hash(0x20);
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(1), b2, 0, fake_sig(0x04)));
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(3), b2, 2, fake_sig(0x05)));
        assert_eq!(SigCount::<Test>::get(&b2), 2);
        assert_ok!(BlsConsensus::finalize_block(RuntimeOrigin::root(), b2, fake_sig(0xF2)));
        assert_eq!(FinalizedCount::<Test>::get(), 2);

        // block 3: only one validator — cannot finalize
        let b3 = block_hash(0x30);
        assert_ok!(BlsConsensus::submit_partial_sig(RuntimeOrigin::signed(2), b3, 1, fake_sig(0x06)));
        assert_noop!(
            BlsConsensus::finalize_block(RuntimeOrigin::root(), b3, fake_sig(0xF3)),
            Error::<Test>::ThresholdNotMet
        );

        // confirm state
        assert!(FinalizedBlocks::<Test>::contains_key(&b1));
        assert!(FinalizedBlocks::<Test>::contains_key(&b2));
        assert!(!FinalizedBlocks::<Test>::contains_key(&b3));
    });
}