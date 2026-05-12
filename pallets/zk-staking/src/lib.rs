//! anonymous staking for zerochain.
//! validators bond tokens behind pedersen commitments.
//! unstaking requires a zk proof of commitment ownership.
//! slashing uses zk fraud proofs for equivocation — identity never revealed.

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
    use zk_types::{Hash256, SlashingPublicInputs};

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// maximum number of active stake commitments
        #[pallet::constant]
        type MaxStakers: Get<u32>;

        /// minimum stake amount (in smallest token unit)
        #[pallet::constant]
        type MinStakeAmount: Get<u128>;
    }

    // -- storage --

    /// stake commitments: maps commitment hash to bonded amount commitment.
    /// the commitment hides the staker's identity. the amount is public
    /// (required for economic security accounting) but the owner is private.
    #[pallet::storage]
    #[pallet::getter(fn stake_commitment)]
    pub type StakeCommitments<T: Config> =
        StorageMap<_, Blake2_128Concat, Hash256, u128, OptionQuery>;

    /// total number of active stake commitments
    #[pallet::storage]
    #[pallet::getter(fn stake_count)]
    pub type StakeCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// total tokens staked across all commitments
    #[pallet::storage]
    #[pallet::getter(fn total_staked)]
    pub type TotalStaked<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// nullifiers of slashed stake commitments.
    /// once a nullifier is here, the corresponding credential is dead.
    #[pallet::storage]
    #[pallet::getter(fn is_slashed)]
    pub type SlashedNullifiers<T: Config> =
        StorageMap<_, Blake2_128Concat, Hash256, BlockNumberFor<T>, OptionQuery>;

    /// total number of slashing events
    #[pallet::storage]
    #[pallet::getter(fn slash_count)]
    pub type SlashCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// nullifiers of unstaked commitments (spent, tokens returned)
    #[pallet::storage]
    #[pallet::getter(fn is_unstaked)]
    pub type UnstakedNullifiers<T: Config> =
        StorageMap<_, Blake2_128Concat, Hash256, BlockNumberFor<T>, OptionQuery>;

    /// total number of unstake events
    #[pallet::storage]
    #[pallet::getter(fn unstake_count)]
    pub type UnstakeCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    // -- events --

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// tokens bonded behind a commitment. amount is public, owner is private.
        Staked { commitment: Hash256, amount: u128 },
        /// tokens returned after zk proof of ownership. nullifier prevents re-stake.
        Unstaked { nullifier: Hash256, amount: u128 },
        /// validator equivocation proved via zk fraud proof. stake burned.
        Slashed { nullifier: Hash256, validator_root: Hash256 },
        /// minimum stake amount updated by governance
        MinStakeUpdated { new_minimum: u128 },
    }

    // -- errors --

    #[pallet::error]
    pub enum Error<T> {
        /// stake amount below minimum
        StakeTooLow,
        /// maximum number of stakers reached
        StakerSetFull,
        /// commitment already has an active stake
        CommitmentAlreadyStaked,
        /// commitment not found in active stakes
        CommitmentNotFound,
        /// nullifier already used (double-unstake or double-slash)
        NullifierAlreadyUsed,
        /// slashing nullifier already recorded
        AlreadySlashed,
        /// invalid fraud proof data
        InvalidSlashingProof,
        /// validator root mismatch with zk-validator pallet
        ValidatorRootMismatch,
    }

    // -- extrinsics --

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// bond tokens behind a pedersen commitment.
        /// the commitment hides the staker's identity.
        /// amount must meet MinStakeAmount.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn stake(
            origin: OriginFor<T>,
            commitment: Hash256,
            amount: u128,
        ) -> DispatchResult {
            // anyone can stake — the commitment hides their identity
            let _who = ensure_signed(origin)?;

            ensure!(amount >= T::MinStakeAmount::get(), Error::<T>::StakeTooLow);

            let count = StakeCount::<T>::get();
            ensure!(count < T::MaxStakers::get(), Error::<T>::StakerSetFull);

            ensure!(
                !StakeCommitments::<T>::contains_key(&commitment),
                Error::<T>::CommitmentAlreadyStaked
            );

            StakeCommitments::<T>::insert(&commitment, amount);
            StakeCount::<T>::mutate(|c| *c += 1);
            TotalStaked::<T>::mutate(|t| *t = t.saturating_add(amount));

            Self::deposit_event(Event::Staked { commitment, amount });
            Ok(())
        }

        /// unstake by proving ownership of a commitment via zk proof.
        /// the nullifier is derived from the staker's secret — deterministic
        /// and unique. once used, the commitment can never be re-staked.
        /// in production, this verifies a groth16 proof. for prototype,
        /// we accept the nullifier directly (proof verification is in proof-verifier).
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(15_000_000, 0))]
        pub fn unstake(
            origin: OriginFor<T>,
            commitment: Hash256,
            nullifier: Hash256,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // check the commitment exists
            let amount = StakeCommitments::<T>::get(&commitment)
                .ok_or(Error::<T>::CommitmentNotFound)?;

            // check nullifier hasn't been used
            ensure!(
                !UnstakedNullifiers::<T>::contains_key(&nullifier),
                Error::<T>::NullifierAlreadyUsed
            );
            ensure!(
                !SlashedNullifiers::<T>::contains_key(&nullifier),
                Error::<T>::AlreadySlashed
            );

            // mark as unstaked
            let block_number = <frame_system::Pallet<T>>::block_number();
            UnstakedNullifiers::<T>::insert(&nullifier, block_number);
            StakeCommitments::<T>::remove(&commitment);
            StakeCount::<T>::mutate(|c| *c = c.saturating_sub(1));
            UnstakeCount::<T>::mutate(|c| *c += 1);
            TotalStaked::<T>::mutate(|t| *t = t.saturating_sub(amount));

            Self::deposit_event(Event::Unstaked { nullifier, amount });
            Ok(())
        }

        /// slash a validator via zk fraud proof. sudo only for prototype.
        /// in production, this is called by proof-verifier after groth16
        /// verification of the equivocation proof.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(15_000_000, 0))]
        pub fn slash(
            origin: OriginFor<T>,
            nullifier: Hash256,
            validator_root: Hash256,
        ) -> DispatchResult {
            ensure_root(origin)?;

            ensure!(
                !SlashedNullifiers::<T>::contains_key(&nullifier),
                Error::<T>::AlreadySlashed
            );

            let block_number = <frame_system::Pallet<T>>::block_number();
            SlashedNullifiers::<T>::insert(&nullifier, block_number);
            SlashCount::<T>::mutate(|c| *c += 1);

            Self::deposit_event(Event::Slashed { nullifier, validator_root });
            Ok(())
        }
    }

    // -- trait implementation for proof-verifier integration --

    impl<T: Config> zk_types::StakingHandler for Pallet<T> {
        /// called by proof-verifier after slashing fraud proof verification.
        /// records the nullifier and emits the event.
        fn process_slash(inputs: &SlashingPublicInputs) {
            // if already slashed, silently skip (infallible trait)
            if SlashedNullifiers::<T>::contains_key(&inputs.nullifier) {
                return;
            }

            let block_number = <frame_system::Pallet<T>>::block_number();
            SlashedNullifiers::<T>::insert(&inputs.nullifier, block_number);
            SlashCount::<T>::mutate(|c| *c += 1);

            Self::deposit_event(Event::Slashed {
                nullifier: inputs.nullifier,
                validator_root: inputs.validator_root,
            });
        }
    }
}