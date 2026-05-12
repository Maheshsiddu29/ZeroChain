//! bls threshold signature aggregation for zerochain.
//! validators submit partial bls signatures for blocks.
//! once threshold is met, signatures aggregate into one
//! that proves consensus without revealing which validators signed.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

extern crate alloc;
use alloc::vec::Vec;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use zk_types::Hash256;

    /// bls12-381 public key size (48 bytes compressed)
    pub const BLS_PUBKEY_SIZE: usize = 48;
    /// bls12-381 signature size (96 bytes compressed)
    pub const BLS_SIG_SIZE: usize = 96;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// maximum number of validators that can submit partial sigs per block
        #[pallet::constant]
        type MaxSigners: Get<u32>;

        /// maximum size of a BLS signature in bytes
        #[pallet::constant]
        type MaxSignatureSize: Get<u32>;

        /// maximum size of a BLS public key in bytes
        #[pallet::constant]
        type MaxKeySize: Get<u32>;
    }

    // -- storage --

    /// aggregate public key from DKG ceremony (BLS12-381).
    /// set once at genesis or via sudo. all partial sigs verify against this.
    #[pallet::storage]
    #[pallet::getter(fn aggregate_public_key)]
    pub type AggregatePublicKey<T: Config> =
        StorageValue<_, BoundedVec<u8, T::MaxKeySize>, OptionQuery>;

    /// threshold config: t-of-n. t sigs needed out of n total validators.
    #[pallet::storage]
    #[pallet::getter(fn threshold)]
    pub type Threshold<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// total number of signers (n in t-of-n)
    #[pallet::storage]
    #[pallet::getter(fn total_signers)]
    pub type TotalSigners<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// partial signatures collected for a block hash.
    /// maps block_hash -> vec of (signer_index, partial_sig).
    #[pallet::storage]
    #[pallet::getter(fn partial_sigs)]
    pub type PartialSignatures<T: Config> =
        StorageMap<_, Blake2_128Concat, Hash256, BoundedVec<(u32, BoundedVec<u8, T::MaxSignatureSize>), T::MaxSigners>, ValueQuery>;

    /// count of partial sigs for a block hash
    #[pallet::storage]
    #[pallet::getter(fn sig_count)]
    pub type SigCount<T: Config> =
        StorageMap<_, Blake2_128Concat, Hash256, u32, ValueQuery>;

    /// finalized blocks: block_hash -> aggregate signature
    #[pallet::storage]
    #[pallet::getter(fn finalized_block)]
    pub type FinalizedBlocks<T: Config> =
        StorageMap<_, Blake2_128Concat, Hash256, BoundedVec<u8, T::MaxSignatureSize>, OptionQuery>;

    /// total blocks finalized via BLS threshold
    #[pallet::storage]
    #[pallet::getter(fn finalized_count)]
    pub type FinalizedCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    // -- events --

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// aggregate public key set (from DKG or sudo)
        AggregateKeySet { key_size: u32 },
        /// threshold configuration updated
        ThresholdUpdated { threshold: u32, total_signers: u32 },
        /// partial signature submitted by a validator
        PartialSigSubmitted { block_hash: Hash256, signer_index: u32, sig_count: u32 },
        /// threshold met — block finalized with aggregate signature
        BlockFinalized { block_hash: Hash256, sig_count: u32 },
        /// threshold reached but not yet finalized (waiting for aggregation)
        ThresholdReached { block_hash: Hash256, sig_count: u32, threshold: u32 },
    }

    // -- errors --

    #[pallet::error]
    pub enum Error<T> {
        /// no aggregate public key registered
        NoAggregateKey,
        /// threshold not configured
        ThresholdNotSet,
        /// signer index out of range
        InvalidSignerIndex,
        /// this signer already submitted for this block
        DuplicateSignature,
        /// signature bytes too large
        SignatureTooLarge,
        /// public key bytes too large
        KeyTooLarge,
        /// block already finalized
        AlreadyFinalized,
        /// not enough partial sigs to finalize
        ThresholdNotMet,
        /// invalid aggregate signature (verification failed)
        InvalidAggregateSignature,
        /// threshold must be > 0 and <= total_signers
        InvalidThreshold,
    }

    // -- extrinsics --

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// set the aggregate public key from DKG ceremony. sudo only.
        /// in production, this comes from FROST DKG. for devnet, hardcoded.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn set_aggregate_key(
            origin: OriginFor<T>,
            key_bytes: Vec<u8>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let bounded_key: BoundedVec<u8, T::MaxKeySize> = key_bytes
                .try_into()
                .map_err(|_| Error::<T>::KeyTooLarge)?;

            let key_size = bounded_key.len() as u32;
            AggregatePublicKey::<T>::put(bounded_key);
            Self::deposit_event(Event::AggregateKeySet { key_size });
            Ok(())
        }

        /// set threshold parameters. sudo only.
        /// threshold = minimum sigs needed. total_signers = total validators.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(5_000_000, 0))]
        pub fn set_threshold(
            origin: OriginFor<T>,
            threshold: u32,
            total_signers: u32,
        ) -> DispatchResult {
            ensure_root(origin)?;

            ensure!(threshold > 0 && threshold <= total_signers, Error::<T>::InvalidThreshold);

            Threshold::<T>::put(threshold);
            TotalSigners::<T>::put(total_signers);
            Self::deposit_event(Event::ThresholdUpdated { threshold, total_signers });
            Ok(())
        }

        /// submit a partial BLS signature for a block.
        /// signer_index identifies which validator share is being used.
        /// the actual validator identity remains hidden behind the ZK membership proof.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(15_000_000, 0))]
        pub fn submit_partial_sig(
            origin: OriginFor<T>,
            block_hash: Hash256,
            signer_index: u32,
            partial_sig: Vec<u8>,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // check preconditions
            ensure!(AggregatePublicKey::<T>::get().is_some(), Error::<T>::NoAggregateKey);
            let total = TotalSigners::<T>::get();
            ensure!(total > 0, Error::<T>::ThresholdNotSet);
            ensure!(signer_index < total, Error::<T>::InvalidSignerIndex);
            ensure!(!FinalizedBlocks::<T>::contains_key(&block_hash), Error::<T>::AlreadyFinalized);

            let bounded_sig: BoundedVec<u8, T::MaxSignatureSize> = partial_sig
                .try_into()
                .map_err(|_| Error::<T>::SignatureTooLarge)?;

            // check no duplicate from this signer
            PartialSignatures::<T>::try_mutate(&block_hash, |sigs| -> DispatchResult {
                let already = sigs.iter().any(|(idx, _)| *idx == signer_index);
                ensure!(!already, Error::<T>::DuplicateSignature);

                sigs.try_push((signer_index, bounded_sig))
                    .map_err(|_| Error::<T>::DuplicateSignature)?;
                Ok(())
            })?;

            let count = SigCount::<T>::mutate(&block_hash, |c| { *c += 1; *c });

            Self::deposit_event(Event::PartialSigSubmitted {
                block_hash,
                signer_index,
                sig_count: count,
            });

            // check if threshold is reached
            let threshold = Threshold::<T>::get();
            if threshold > 0 && count >= threshold {
                Self::deposit_event(Event::ThresholdReached {
                    block_hash,
                    sig_count: count,
                    threshold,
                });
            }

            Ok(())
        }

        /// finalize a block with an aggregate BLS signature.
        /// in production, this verifies the aggregate sig against the aggregate key.
        /// for prototype, we check threshold is met and store the sig.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(20_000_000, 0))]
        pub fn finalize_block(
            origin: OriginFor<T>,
            block_hash: Hash256,
            aggregate_sig: Vec<u8>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            ensure!(!FinalizedBlocks::<T>::contains_key(&block_hash), Error::<T>::AlreadyFinalized);
            ensure!(AggregatePublicKey::<T>::get().is_some(), Error::<T>::NoAggregateKey);

            let threshold = Threshold::<T>::get();
            let count = SigCount::<T>::get(&block_hash);
            ensure!(count >= threshold, Error::<T>::ThresholdNotMet);

            let bounded_sig: BoundedVec<u8, T::MaxSignatureSize> = aggregate_sig
                .try_into()
                .map_err(|_| Error::<T>::SignatureTooLarge)?;

            // TODO: verify aggregate_sig against AggregatePublicKey using blst
            // cfg(feature = "std") gating for real BLS verification, same as proof-verifier

            FinalizedBlocks::<T>::insert(&block_hash, bounded_sig);
            let sig_count = count;
            FinalizedCount::<T>::mutate(|c| *c += 1);

            Self::deposit_event(Event::BlockFinalized { block_hash, sig_count });
            Ok(())
        }
    }
}