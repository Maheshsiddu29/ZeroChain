//! BLS Consensus Pallet Tests

#[cfg(test)]
mod tests {
    use crate::*;
    use crate::pallet::{PartialSignatures, ThresholdConfigStorage};
    use frame_support::assert_ok;
    use super::super::mock::*;

    fn dummy_signature_bytes(id: u8) -> [u8; 96] {
        let mut sig = [0u8; 96];
        sig[0] = id;
        sig
    }

    #[test]
    fn test_initialize_consensus() {
        new_test_ext().execute_with(|| {
            assert_ok!(BlsConsensus::initialize(RuntimeOrigin::root(), 2));

            let config = ThresholdConfigStorage::<Test>::get();
            assert_eq!(config.threshold, 2);
            assert_eq!(config.total, 3);
        });
    }

    #[test]
    fn test_submit_partial_signature() {
        new_test_ext().execute_with(|| {
            assert_ok!(BlsConsensus::initialize(RuntimeOrigin::root(), 2));

            let block_number = 1u32;
            let signature = dummy_signature_bytes(1);

            assert_ok!(BlsConsensus::submit_partial_sig(
                RuntimeOrigin::signed(1),
                0,
                block_number,
                signature,
            ));

            assert_eq!(BlsConsensus::partial_sig_count(), 1);
        });
    }

    #[test]
    fn test_duplicate_signature_rejected() {
        new_test_ext().execute_with(|| {
            assert_ok!(BlsConsensus::initialize(RuntimeOrigin::root(), 2));

            let block_number = 1u32;
            let signature = dummy_signature_bytes(1);

            assert_ok!(BlsConsensus::submit_partial_sig(
                RuntimeOrigin::signed(1),
                0,
                block_number,
                signature,
            ));

            let result = BlsConsensus::submit_partial_sig(
                RuntimeOrigin::signed(2),
                0,
                block_number,
                signature,
            );

            assert!(result.is_err());
        });
    }

    #[test]
    fn test_finalize_block_with_threshold() {
        new_test_ext().execute_with(|| {
            assert_ok!(BlsConsensus::initialize(RuntimeOrigin::root(), 2));

            let block_number = 1u32;
            let sig1 = dummy_signature_bytes(1);
            let sig2 = dummy_signature_bytes(2);

            assert_ok!(BlsConsensus::submit_partial_sig(
                RuntimeOrigin::signed(1),
                0,
                block_number,
                sig1,
            ));

            assert_ok!(BlsConsensus::submit_partial_sig(
                RuntimeOrigin::signed(2),
                1,
                block_number,
                sig2,
            ));

            assert!(BlsConsensus::partial_sig_count() >= 2);

            assert_ok!(BlsConsensus::finalize_block(
                RuntimeOrigin::root(),
                block_number,
            ));

            assert_eq!(BlsConsensus::partial_sig_count(), 0);
        });
    }

    #[test]
    fn test_finalize_below_threshold_fails() {
        new_test_ext().execute_with(|| {
            assert_ok!(BlsConsensus::initialize(RuntimeOrigin::root(), 2));

            let block_number = 1u32;
            let sig = dummy_signature_bytes(1);

            assert_ok!(BlsConsensus::submit_partial_sig(
                RuntimeOrigin::signed(1),
                0,
                block_number,
                sig,
            ));

            let result = BlsConsensus::finalize_block(
                RuntimeOrigin::root(),
                block_number,
            );

            assert!(result.is_err());
        });
    }

    #[test]
    fn test_epoch_transition() {
        new_test_ext().execute_with(|| {
            assert_ok!(BlsConsensus::initialize(RuntimeOrigin::root(), 2));
            assert_eq!(BlsConsensus::current_epoch(), 0);

            assert_ok!(BlsConsensus::start_new_epoch(RuntimeOrigin::root()));
            assert_eq!(BlsConsensus::current_epoch(), 1);
        });
    }

    #[test]
    fn test_multiple_blocks_sequential() {
        new_test_ext().execute_with(|| {
            assert_ok!(BlsConsensus::initialize(RuntimeOrigin::root(), 2));

            for block_num in 1..=3 {
                let sig1 = dummy_signature_bytes(1);
                let sig2 = dummy_signature_bytes(2);

                assert_ok!(BlsConsensus::submit_partial_sig(
                    RuntimeOrigin::signed(1),
                    0,
                    block_num,
                    sig1,
                ));

                assert_ok!(BlsConsensus::submit_partial_sig(
                    RuntimeOrigin::signed(2),
                    1,
                    block_num,
                    sig2,
                ));

                assert_ok!(BlsConsensus::finalize_block(
                    RuntimeOrigin::root(),
                    block_num,
                ));
            }
        });
    }

    #[test]
    fn test_dkg_basic_protocol() {
        use crate::dkg::DkgCoordinator;

        let mut coordinator = DkgCoordinator::new(3, 2).unwrap();
        let result = coordinator.execute();

        assert!(result.is_ok());
        let secret_keys = result.unwrap();
        assert_eq!(secret_keys.len(), 3);
    }

    #[test]
    fn test_aggregator_basic_operations() {
        use crate::aggregation::BlsAggregator;

        let apk = BlsPublicKey::new([1u8; 48]);
        let mut agg = BlsAggregator::new(apk, 2);

        let block_hash = [1u8; 32];
        let sig1_bytes = dummy_signature_bytes(1);
        let sig2_bytes = dummy_signature_bytes(2);

        let sig1 = PartialSignature::new(0, BlsSignature::new(sig1_bytes), block_hash);
        let sig2 = PartialSignature::new(1, BlsSignature::new(sig2_bytes), block_hash);

        assert!(agg.add_partial_signature(sig1).is_ok());
        assert!(agg.add_partial_signature(sig2).is_ok());

        let result = agg.aggregate();
        assert!(result.is_ok());

        let agg_sig = result.unwrap();
        assert_eq!(agg_sig.signature_count, 2);
    }
}