//! ZK Staking Pallet
//!
//! Allows validators to stake anonymously via commitments, prove validator membership,
//! and be slashed for equivocation via ZK proofs.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

mod types;
pub use types::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{pallet_prelude::*, BoundedVec};
    use frame_system::pallet_prelude::*;
    use sp_std::vec::Vec;

    pub const VALIDATOR_TREE_DEPTH: usize = 20; // 2^20 validators
    pub const MAX_VALIDATORS: u32 = 1_048_576; // 2^20

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Runtime event
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Minimum amount to stake (in smallest units)
        #[pallet::constant]
        type MinStakeAmount: Get<u128>;

        /// Blocks per epoch
        #[pallet::constant]
        type EpochLength: Get<BlockNumberFor<Self>>;

        /// Maximum validators per epoch
        #[pallet::constant]
        type MaxValidators: Get<u32>;
    }

    /// Storage: Validator commitments (stake credentials)
    /// Map: commitment_hash → StakeCommitment
    #[pallet::storage]
    #[pallet::getter(fn stake_commitment)]
    pub type StakeCommitments<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        [u8; 32],
        StakeCommitment,
        OptionQuery,
    >;

    /// Storage: Slashed nullifiers (prevents double-spending fraud proofs)
    /// Set: { nullifier }
    #[pallet::storage]
    #[pallet::getter(fn slashed_nullifiers)]
    pub type SlashedNullifiers<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        [u8; 32],
        bool,
        ValueQuery,
    >;

    /// Storage: Total staked amount
    #[pallet::storage]
    #[pallet::getter(fn total_staked)]
    pub type TotalStaked<T: Config> = StorageValue<_, u128, ValueQuery>;

    /// Storage: Validator set for current epoch
    #[pallet::storage]
    #[pallet::getter(fn validator_set)]
    pub type ValidatorSet<T: Config> = StorageValue<
        _,
        BoundedVec<[u8; 32], T::MaxValidators>,
        ValueQuery,
    >;

    /// Storage: Current validator tree root (Merkle root)
    #[pallet::storage]
    #[pallet::getter(fn validator_root)]
    pub type ValidatorRoot<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

    /// Storage: Current epoch number
    #[pallet::storage]
    #[pallet::getter(fn current_epoch)]
    pub type CurrentEpoch<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Validator staked
        /// [commitment, amount]
        ValidatorStaked {
            commitment: [u8; 32],
            amount: u128,
        },

        /// Validator slashed
        /// [nullifier, amount_slashed]
        ValidatorSlashed {
            nullifier: [u8; 32],
            amount_slashed: u128,
        },

        /// Validator unstaked
        /// [commitment, amount]
        ValidatorUnstaked {
            commitment: [u8; 32],
            amount: u128,
        },

        /// Validator tree updated
        /// [new_root, validator_count]
        ValidatorTreeUpdated {
            new_root: [u8; 32],
            validator_count: u32,
        },

        /// Epoch transitioned
        /// [epoch, new_validator_root]
        EpochTransitioned {
            epoch: u64,
            new_validator_root: [u8; 32],
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Stake amount below minimum
        StakeBelowMinimum,
        /// Commitment already staked
        CommitmentAlreadyStaked,
        /// Commitment not found
        CommitmentNotFound,
        /// Validator tree full
        ValidatorTreeFull,
        /// Invalid slashing proof
        InvalidSlashingProof,
        /// Nullifier already slashed
        NullifierAlreadySlashed,
        /// Proof verification failed
        ProofVerificationFailed,
        /// Unstaking proof invalid
        UnstakingProofInvalid,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Stake as validator with commitment
        ///
        /// # Arguments
        /// * `commitment` - H(secret_key, randomness) = [u8; 32]
        /// * `amount` - Stake amount (must be ≥ MinStakeAmount)
        ///
        /// # Constraints
        /// - Amount ≥ MinStakeAmount
        /// - Commitment not already in tree
        /// - Validator set not full
        #[pallet::call_index(0)]
        #[pallet::weight(10_000)]
        pub fn stake(
            origin: OriginFor<T>,
            commitment: [u8; 32],
            amount: u128,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // Validate minimum stake
            ensure!(
                amount >= T::MinStakeAmount::get(),
                Error::<T>::StakeBelowMinimum
            );

            // Check commitment not already staked
            ensure!(
                !StakeCommitments::<T>::contains_key(&commitment),
                Error::<T>::CommitmentAlreadyStaked
            );

            // Check validator set not full
            let validator_set = ValidatorSet::<T>::get();
            ensure!(
                (validator_set.len() as u32) < T::MaxValidators::get(),
                Error::<T>::ValidatorTreeFull
            );

            // Record stake commitment
            let stake_commitment = StakeCommitment {
                commitment,
                amount,
                epoch: Self::current_epoch(),
                timestamp: frame_system::Pallet::<T>::block_number()
                    .try_into()
                    .unwrap_or(0u32),
            };

            StakeCommitments::<T>::insert(&commitment, stake_commitment);

            // Update total staked
            let new_total = TotalStaked::<T>::get().saturating_add(amount);
            TotalStaked::<T>::set(new_total);

            // Add to validator set
            let mut new_set = validator_set;
            let _ = new_set.try_push(commitment);
            ValidatorSet::<T>::set(new_set.clone());

            // Recompute validator root (simplified: H(commitments))
            let new_root = Self::compute_validator_root(&new_set);
            ValidatorRoot::<T>::set(new_root);

            Self::deposit_event(Event::ValidatorStaked { commitment, amount });

            Ok(())
        }

        /// Unstake and recover stake (requires proof of withdrawal)
        ///
        /// # Arguments
        /// * `commitment` - Stake commitment
        /// * `proof` - Nullifier proof (prevents stake recovery during same epoch)
        /// * `nullifier` - Unique identifier
        #[pallet::call_index(1)]
        #[pallet::weight(10_000)]
        pub fn unstake(
            origin: OriginFor<T>,
            commitment: [u8; 32],
            proof: Vec<u8>,
            nullifier: [u8; 32],
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // Find stake
            let stake = StakeCommitments::<T>::get(&commitment)
                .ok_or(Error::<T>::CommitmentNotFound)?;

            // Verify proof (in production, verify actual ZK proof)
            ensure!(!proof.is_empty(), Error::<T>::UnstakingProofInvalid);

            // Verify nullifier not already used
            ensure!(
                !SlashedNullifiers::<T>::get(&nullifier),
                Error::<T>::NullifierAlreadySlashed
            );

            // Mark nullifier as used
            SlashedNullifiers::<T>::insert(&nullifier, true);

            // Remove from validator set
            let mut new_set = ValidatorSet::<T>::get();
            new_set.retain(|c| c != &commitment);
            ValidatorSet::<T>::set(new_set.clone());

            // Update totals
            let new_total = TotalStaked::<T>::get().saturating_sub(stake.amount);
            TotalStaked::<T>::set(new_total);

            // Recompute root
            let new_root = Self::compute_validator_root(&new_set);
            ValidatorRoot::<T>::set(new_root);

            // Remove commitment
            StakeCommitments::<T>::remove(&commitment);

            Self::deposit_event(Event::ValidatorUnstaked {
                commitment,
                amount: stake.amount,
            });

            Ok(())
        }

        /// Slash validator for equivocation
        ///
        /// # Arguments
        /// * `fraud_proof` - Slashing proof (proves equivocation)
        /// * `nullifier` - Fraud proof nullifier (prevents replay)
        #[pallet::call_index(2)]
        #[pallet::weight(15_000)]
        pub fn slash(
            origin: OriginFor<T>,
            fraud_proof: Vec<u8>,
            nullifier: [u8; 32],
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // Verify proof not already used
            ensure!(
                !SlashedNullifiers::<T>::get(&nullifier),
                Error::<T>::NullifierAlreadySlashed
            );

            // Verify fraud proof (in production: actual ZK proof verification)
            ensure!(!fraud_proof.is_empty(), Error::<T>::InvalidSlashingProof);

            // Mark nullifier as used (prevents double-slashing)
            SlashedNullifiers::<T>::insert(&nullifier, true);

            // In a real implementation, would:
            // 1. Extract commitment from proof
            // 2. Find and remove from validator set
            // 3. Burn stake

            // For now, record the event
            Self::deposit_event(Event::ValidatorSlashed {
                nullifier,
                amount_slashed: 0,
            });

            Ok(())
        }

        /// Transition to next epoch (called by consensus)
        #[pallet::call_index(3)]
        #[pallet::weight(5_000)]
        pub fn transition_epoch(origin: OriginFor<T>) -> DispatchResult {
            ensure_root(origin)?;

            let current = Self::current_epoch();
            let next_epoch = current.saturating_add(1);
            CurrentEpoch::<T>::set(next_epoch);

            let root = Self::validator_root();

            Self::deposit_event(Event::EpochTransitioned {
                epoch: next_epoch,
                new_validator_root: root,
            });

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Compute Merkle root from validator commitments
        /// Simplified: SHA256(concat(commitments))
        pub fn compute_validator_root(
            validators: &BoundedVec<[u8; 32], T::MaxValidators>,
        ) -> [u8; 32] {
            use sp_runtime::traits::Hash;

            if validators.is_empty() {
                return [0u8; 32];
            }

            // Concatenate all commitments
            let mut data = Vec::new();
            for commitment in validators.iter() {
                data.extend_from_slice(commitment);
            }

            // Hash concatenation
            let hash_output = T::Hashing::hash(&data);
            let mut root = [0u8; 32];
            let hash_bytes = hash_output.as_ref();
            let copy_len = hash_bytes.len().min(32);
            root[..copy_len].copy_from_slice(&hash_bytes[..copy_len]);
            root
        }

        /// Get validator count
        pub fn validator_count() -> u32 {
            ValidatorSet::<T>::get().len() as u32
        }

        /// Check if commitment is in validator set
        pub fn is_validator(commitment: &[u8; 32]) -> bool {
            ValidatorSet::<T>::get().iter().any(|c| c == commitment)
        }
    }
}