//! private token transfers for zerochain.
//! manages the note commitment tree and nullifier set.
//! called by proof-verifier after groth16 verification passes.

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
    use zk_types::{AssetId, Hash256, TransferPublicInputs, ShieldedTransferHandler, MAX_INPUTS, MAX_OUTPUTS};

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        #[pallet::constant]
        type MaxCommitments: Get<u32>;

        #[pallet::constant]
        type MerkleRootHistory: Get<u32>;
    }

    // -- storage --

    /// note commitments in insertion order (append-only)
    #[pallet::storage]
    #[pallet::getter(fn commitments)]
    pub type Commitments<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, Hash256, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn commitment_count)]
    pub type CommitmentCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// spent nullifiers. if it exists here, the note is already spent.
    #[pallet::storage]
    #[pallet::getter(fn nullifier_exists)]
    pub type NullifierSet<T: Config> =
        StorageMap<_, Blake2_128Concat, Hash256, BlockNumberFor<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn nullifier_count)]
    pub type NullifierCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// recent valid merkle roots (ring buffer, keeps last N)
    #[pallet::storage]
    #[pallet::getter(fn merkle_roots)]
    pub type MerkleRoots<T: Config> =
        StorageMap<_, Blake2_128Concat, u32, Hash256, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn merkle_root_index)]
    pub type MerkleRootIndex<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn current_merkle_root)]
    pub type CurrentMerkleRoot<T: Config> = StorageValue<_, Hash256, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn transfer_count)]
    pub type TransferCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    // -- events --

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ShieldedTransferProcessed { nullifiers_added: u32, commitments_added: u32, asset_id: AssetId },
        MerkleRootUpdated { root: Hash256 },
        CommitmentInserted { index: u64, commitment: Hash256 },
    }

    // -- errors --

    #[pallet::error]
    pub enum Error<T> {
        NullifierAlreadySpent,
        InvalidMerkleRoot,
        TooManyNullifiers,
        TooManyCommitments,
        TreeFull,
        NoMerkleRoot,
    }

    // -- extrinsics --

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// testing extrinsic: process a transfer without proof verification.
        /// in production, proof-verifier calls process_verified_transfer directly.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn process_transfer(
            origin: OriginFor<T>,
            inputs: TransferPublicInputs,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Self::do_process_transfer(&inputs)
        }

        /// set merkle root. sudo only for prototype.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn update_merkle_root(
            origin: OriginFor<T>,
            root: Hash256,
        ) -> DispatchResult {
            ensure_root(origin)?;
            let history_size = T::MerkleRootHistory::get();
            let idx = MerkleRootIndex::<T>::get();
            MerkleRoots::<T>::insert(idx, root);
            MerkleRootIndex::<T>::put((idx + 1) % history_size);
            CurrentMerkleRoot::<T>::put(root);
            Self::deposit_event(Event::MerkleRootUpdated { root });
            Ok(())
        }
    }

    // -- internal --

    impl<T: Config> Pallet<T> {
        fn do_process_transfer(inputs: &TransferPublicInputs) -> DispatchResult {
            ensure!(inputs.nullifiers.len() <= MAX_INPUTS as usize, Error::<T>::TooManyNullifiers);
            ensure!(inputs.output_commitments.len() <= MAX_OUTPUTS as usize, Error::<T>::TooManyCommitments);

            // check merkle root (skip if none set yet, for bootstrapping)
            if CurrentMerkleRoot::<T>::get().is_some() {
                ensure!(Self::is_valid_merkle_root(&inputs.merkle_root), Error::<T>::InvalidMerkleRoot);
            }

            // check no double spends
            for nullifier in &inputs.nullifiers {
                ensure!(!NullifierSet::<T>::contains_key(nullifier), Error::<T>::NullifierAlreadySpent);
            }

            // mark nullifiers spent
            let block_number = <frame_system::Pallet<T>>::block_number();
            for nullifier in &inputs.nullifiers {
                NullifierSet::<T>::insert(nullifier, block_number);
            }
            NullifierCount::<T>::mutate(|c| *c = c.saturating_add(inputs.nullifiers.len() as u64));

            // append output commitments
            let mut count = CommitmentCount::<T>::get();
            for commitment in &inputs.output_commitments {
                Commitments::<T>::insert(count, commitment);
                Self::deposit_event(Event::CommitmentInserted { index: count, commitment: *commitment });
                count = count.saturating_add(1);
            }
            CommitmentCount::<T>::put(count);

            TransferCount::<T>::mutate(|c| *c = c.saturating_add(1));
            Self::deposit_event(Event::ShieldedTransferProcessed {
                nullifiers_added: inputs.nullifiers.len() as u32,
                commitments_added: inputs.output_commitments.len() as u32,
                asset_id: inputs.asset_id,
            });

            Ok(())
        }

        fn is_valid_merkle_root(root: &Hash256) -> bool {
            if let Some(current) = CurrentMerkleRoot::<T>::get() {
                if &current == root { return true; }
            }
            let history_size = T::MerkleRootHistory::get();
            for i in 0..history_size {
                if let Some(stored) = MerkleRoots::<T>::get(i) {
                    if &stored == root { return true; }
                }
            }
            false
        }
    }

    impl<T: Config> ShieldedTransferHandler for Pallet<T> {
        fn process_verified_transfer(inputs: &TransferPublicInputs) {
            let _ = Self::do_process_transfer(inputs);
        }
    }
}