//! BLS12-381 Consensus Pallet with FROST DKG

#![cfg_attr(not(feature = "std"), no_std)]

mod types;
pub use types::*;

#[cfg(feature = "std")]
mod dkg;
#[cfg(feature = "std")]
pub use dkg::{DkgCoordinator, DkgParticipant};

#[cfg(feature = "std")]
mod aggregation;
#[cfg(feature = "std")]
pub use aggregation::{BlsAggregator, AggregationError};

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;
    use crate::types::*;

    const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        #[pallet::constant]
        type SignatureThreshold: Get<u16>;

        #[pallet::constant]
        type ValidatorCount: Get<u16>;

        #[pallet::constant]
        type MaxPartialSignatures: Get<u32>;
    }

    #[pallet::storage]
    #[pallet::getter(fn aggregate_public_key)]
    pub type AggregatePublicKey<T: Config> = StorageValue<_, BlsPublicKey, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn partial_signatures)]
    pub type PartialSignatures<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        u16,
        PartialSignature,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn threshold_config)]
    pub type ThresholdConfigStorage<T: Config> = StorageValue<_, ThresholdConfig, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn finalized_blocks)]
    pub type FinalizedBlocks<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        [u8; 32],
        FinalizedBlock,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn current_epoch)]
    pub type CurrentEpoch<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn validator_public_keys)]
    pub type ValidatorPublicKeys<T: Config> =
        StorageMap<_, Blake2_128Concat, u16, BlsPublicKey, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        DkgCompleted { epoch: u64 },
        PartialSignatureSubmitted {
            signer_id: u16,
            block_number: u32,
        },
        BlockFinalized {
            block_number: u32,
            signature_count: u16,
        },
        ThresholdReached { epoch: u64 },
        EpochStarted { epoch: u64, threshold: u16 },
    }

    #[pallet::error]
    pub enum Error<T> {
        UnknownSigner,
        DuplicateSignature,
        InvalidSignature,
        MismatchedBlockHash,
        InsufficientSignatures,
        BlockAlreadyFinalized,
        VerificationFailed,
        DkgNotCompleted,
        InvalidThreshold,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn submit_partial_sig(
            origin: OriginFor<T>,
            signer_id: u16,
            block_number: u32,
            signature_bytes: [u8; 96],
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            ensure!(
                ValidatorPublicKeys::<T>::contains_key(signer_id),
                Error::<T>::UnknownSigner
            );

            ensure!(
                !PartialSignatures::<T>::contains_key(signer_id),
                Error::<T>::DuplicateSignature
            );

            let block_hash = Self::block_number_to_hash(block_number);
            let signature = BlsSignature::new(signature_bytes);
            let partial_sig = PartialSignature::new(signer_id, signature, block_hash);
            PartialSignatures::<T>::insert(signer_id, partial_sig);

            Self::deposit_event(Event::PartialSignatureSubmitted {
                signer_id,
                block_number,
            });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(15_000)]
        pub fn finalize_block(
            origin: OriginFor<T>,
            block_number: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let block_hash = Self::block_number_to_hash(block_number);

            ensure!(
                !FinalizedBlocks::<T>::contains_key(&block_hash),
                Error::<T>::BlockAlreadyFinalized
            );

            let sig_count = PartialSignatures::<T>::iter().count() as u16;
            let config = ThresholdConfigStorage::<T>::get();

            ensure!(
                sig_count >= config.threshold,
                Error::<T>::InsufficientSignatures
            );

            let mut signer_bitmap = [0u8; 32];
            for (signer_id, _) in PartialSignatures::<T>::iter() {
                let byte_idx = (signer_id / 8) as usize;
                let bit_idx = signer_id % 8;
                if byte_idx < signer_bitmap.len() {
                    signer_bitmap[byte_idx] |= 1 << bit_idx;
                }
            }

            let mut combined = [0u8; 96];
            for (_, sig) in PartialSignatures::<T>::iter() {
                for i in 0..96 {
                    combined[i] ^= sig.signature.0[i];
                }
            }

            let aggregate_sig = AggregateSignature::new(
                BlsSignature::new(combined),
                block_hash,
                signer_bitmap.to_vec(),
                sig_count,
            );

            let epoch = CurrentEpoch::<T>::get();
            let finalized = FinalizedBlock::new(
                block_hash,
                block_number,
                aggregate_sig,
                epoch,
            );

            FinalizedBlocks::<T>::insert(block_hash, finalized);

            for (signer_id, _) in PartialSignatures::<T>::iter() {
                PartialSignatures::<T>::remove(signer_id);
            }

            Self::deposit_event(Event::BlockFinalized {
                block_number,
                signature_count: sig_count,
            });

            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(50_000)]
        pub fn start_new_epoch(origin: OriginFor<T>) -> DispatchResult {
            ensure_root(origin)?;

            let current = CurrentEpoch::<T>::get();
            let next_epoch = current + 1;
            CurrentEpoch::<T>::set(next_epoch);

            let config = ThresholdConfigStorage::<T>::get();
            let _apk = Self::simulate_dkg();

            Self::deposit_event(Event::EpochStarted {
                epoch: next_epoch,
                threshold: config.threshold,
            });

            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(20_000)]
        pub fn initialize(
            origin: OriginFor<T>,
            threshold: u16,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let total = T::ValidatorCount::get();

            let config = ThresholdConfig::new(total, threshold)
                .map_err(|_| Error::<T>::InvalidThreshold)?;

            ThresholdConfigStorage::<T>::set(config);

            let apk = Self::simulate_dkg();
            AggregatePublicKey::<T>::set(apk);

            CurrentEpoch::<T>::set(0);

            for i in 0..total {
                let mut pk_bytes = [0u8; 48];
                pk_bytes[0] = (i as u8);
                ValidatorPublicKeys::<T>::insert(i, BlsPublicKey::new(pk_bytes));
            }

            Self::deposit_event(Event::DkgCompleted { epoch: 0 });

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn simulate_dkg() -> BlsPublicKey {
            let epoch_bytes = CurrentEpoch::<T>::get().to_le_bytes();
            let mut apk = [0u8; 48];
            for i in 0..48 {
                apk[i] = epoch_bytes[i % 8].wrapping_add(i as u8);
            }
            BlsPublicKey::new(apk)
        }

        fn block_number_to_hash(block_number: u32) -> [u8; 32] {
            let mut hash = [0u8; 32];
            hash[0..4].copy_from_slice(&block_number.to_le_bytes());
            hash
        }

        pub fn partial_sig_count() -> u16 {
            PartialSignatures::<T>::iter().count() as u16
        }

        pub fn is_finalized(block_hash: &[u8; 32]) -> bool {
            FinalizedBlocks::<T>::contains_key(block_hash)
        }

        pub fn get_finalized_block(block_hash: &[u8; 32]) -> Option<FinalizedBlock> {
            FinalizedBlocks::<T>::get(block_hash)
        }
    }
}

pub use pallet::*;