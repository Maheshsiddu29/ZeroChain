//! anonymous validator set for zerochain.
//! validators register credential commitments into a merkle tree
//! and prove membership with halo2 proofs without revealing identity.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

extern crate alloc;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use zk_types::{Hash256, MembershipPublicInputs};

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        #[pallet::constant]
        type MaxValidators: Get<u32>;
    }

    // -- storage --

    /// merkle root of the validator credential tree
    #[pallet::storage]
    #[pallet::getter(fn validator_root)]
    pub type ValidatorRoot<T: Config> = StorageValue<_, Hash256, OptionQuery>;

    /// credential commitments (leaves of the merkle tree)
    #[pallet::storage]
    #[pallet::getter(fn validator_commitment)]
    pub type ValidatorCommitments<T: Config> =
        StorageMap<_, Blake2_128Concat, u32, Hash256, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn validator_count)]
    pub type ValidatorCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn current_epoch)]
    pub type CurrentEpoch<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// nullifiers of slashed credentials
    #[pallet::storage]
    #[pallet::getter(fn is_slashed)]
    pub type SlashedNullifiers<T: Config> =
        StorageMap<_, Blake2_128Concat, Hash256, BlockNumberFor<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn slashed_count)]
    pub type SlashedCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// membership proofs verified this epoch (participation tracking)
    #[pallet::storage]
    #[pallet::getter(fn proofs_this_epoch)]
    pub type ProofsThisEpoch<T: Config> = StorageValue<_, u64, ValueQuery>;

    // -- events --

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ValidatorRegistered { index: u32, commitment: Hash256 },
        ValidatorRootUpdated { root: Hash256 },
        MembershipVerified { epoch: u64, slot: u64 },
        EpochAdvanced { old_epoch: u64, new_epoch: u64 },
        ValidatorSlashed { nullifier: Hash256 },
    }

    // -- errors --

    #[pallet::error]
    pub enum Error<T> {
        ValidatorSetFull,
        CommitmentAlreadyRegistered,
        EpochMismatch,
        ValidatorRootMismatch,
        NoValidatorRoot,
        ValidatorSlashedError,
        AlreadySlashed,
    }

    // -- extrinsics --

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// add a credential commitment. sudo only for prototype.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn register_validator(
            origin: OriginFor<T>,
            commitment: Hash256,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let count = ValidatorCount::<T>::get();
            ensure!(count < T::MaxValidators::get(), Error::<T>::ValidatorSetFull);

            for i in 0..count {
                if let Some(existing) = ValidatorCommitments::<T>::get(i) {
                    ensure!(existing != commitment, Error::<T>::CommitmentAlreadyRegistered);
                }
            }

            ValidatorCommitments::<T>::insert(count, commitment);
            ValidatorCount::<T>::put(count + 1);
            Self::deposit_event(Event::ValidatorRegistered { index: count, commitment });
            Ok(())
        }

        /// set the validator merkle root. sudo only for prototype,
        /// will be computed on-chain with poseidon in production.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn update_validator_root(
            origin: OriginFor<T>,
            root: Hash256,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ValidatorRoot::<T>::put(root);
            Self::deposit_event(Event::ValidatorRootUpdated { root });
            Ok(())
        }

        /// move to next epoch, resets proof counter
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(5_000_000, 0))]
        pub fn advance_epoch(origin: OriginFor<T>) -> DispatchResult {
            ensure_root(origin)?;
            let old_epoch = CurrentEpoch::<T>::get();
            let new_epoch = old_epoch + 1;
            CurrentEpoch::<T>::put(new_epoch);
            ProofsThisEpoch::<T>::put(0);
            Self::deposit_event(Event::EpochAdvanced { old_epoch, new_epoch });
            Ok(())
        }

        /// invalidate a credential by its nullifier. does not reveal which validator.
        #[pallet::call_index(3)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn slash_validator(
            origin: OriginFor<T>,
            nullifier: Hash256,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(!SlashedNullifiers::<T>::contains_key(&nullifier), Error::<T>::AlreadySlashed);
            let block_number = <frame_system::Pallet<T>>::block_number();
            SlashedNullifiers::<T>::insert(&nullifier, block_number);
            SlashedCount::<T>::mutate(|c| *c += 1);
            Self::deposit_event(Event::ValidatorSlashed { nullifier });
            Ok(())
        }
    }

    // -- internal --

    impl<T: Config> Pallet<T> {
        /// called by proof-verifier after halo2 membership proof passes
        pub fn process_verified_membership(inputs: &MembershipPublicInputs) -> DispatchResult {
            let current_epoch = CurrentEpoch::<T>::get();
            ensure!(inputs.epoch == current_epoch, Error::<T>::EpochMismatch);

            let stored_root = ValidatorRoot::<T>::get().ok_or(Error::<T>::NoValidatorRoot)?;
            ensure!(stored_root == inputs.validator_root, Error::<T>::ValidatorRootMismatch);

            ProofsThisEpoch::<T>::mutate(|c| *c += 1);
            Self::deposit_event(Event::MembershipVerified { epoch: inputs.epoch, slot: inputs.slot });
            Ok(())
        }
    }
}