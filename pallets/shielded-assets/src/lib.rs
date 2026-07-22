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
    use frame_support::traits::{Currency, ExistenceRequirement, WithdrawReasons};
    use frame_system::pallet_prelude::*;
    use zk_types::{AssetId, Hash256, TransferPublicInputs, ShieldedTransferHandler, MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID};

    // All-zero 32-byte array used by the fixed-shape circuit to pad unused
    // nullifier and commitment slots. Skip these — they are not real notes.
    const DUMMY_FIELD_ELEMENT: Hash256 = [0u8; 32];

    /// Balance type of T::Currency.
    type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        #[pallet::constant]
        type MaxCommitments: Get<u32>;

        #[pallet::constant]
        type MerkleRootHistory: Get<u32>;

        /// Currency used to burn transparent balance when shielding.
        type Currency: Currency<Self::AccountId>;
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

    // -- genesis --

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub initial_merkle_root: Option<Hash256>,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            if let Some(root) = self.initial_merkle_root {
                CurrentMerkleRoot::<T>::put(root);
                let history_size = T::MerkleRootHistory::get();
                if history_size > 0 {
                    MerkleRoots::<T>::insert(0u32, root);
                    MerkleRootIndex::<T>::put(1u32 % history_size);
                }
            }
        }
    }

    // -- events --

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ShieldedTransferProcessed { nullifiers_added: u32, commitments_added: u32, asset_id: AssetId },
        MerkleRootUpdated { root: Hash256 },
        CommitmentInserted { index: u64, commitment: Hash256 },
        /// Emitted when transparent balance is converted to a shielded note.
        Shielded { commitment: Hash256, amount: BalanceOf<T> },
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
        /// Shield amount is zero; zero-value notes are unspendable by the circuit.
        ZeroAmount,
        /// Shield amount exceeds u64::MAX; the transfer circuit uses u64 for note values.
        AmountTooLarge,
        /// Caller does not have sufficient transparent balance to shield.
        InsufficientBalance,
    }

    // -- extrinsics --

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Convert transparent balance into a shielded note.
        ///
        /// Burns `amount` from the caller's transparent balance (total issuance decreases)
        /// and inserts the commitment cm = Poseidon_t5(owner_pubkey, amount, NATIVE_ASSET_ID,
        /// blinding) into the commitment tree.
        ///
        /// Conservation: the pallet computes cm itself from the same `amount` it debited,
        /// so the commitment value field equals the burned amount by construction — there is
        /// no code path where they differ.
        ///
        /// The resulting note is spendable by the transfer circuit once the Merkle root is
        /// updated to include the new commitment (via `update_merkle_root`).
        ///
        /// AUDITOR NOTE: value-entering operation; requires human cryptographic review before
        /// mainnet deployment.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn shield(
            origin: OriginFor<T>,
            #[pallet::compact] amount: BalanceOf<T>,
            owner_pubkey: Hash256,
            blinding: Hash256,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            // Zero-value notes are unspendable by the transfer circuit (range check).
            ensure!(!amount.is_zero(), Error::<T>::ZeroAmount);

            // The circuit stores note values as u64; ensure the amount fits.
            let amount_u64: u64 = amount.try_into().map_err(|_| Error::<T>::AmountTooLarge)?;

            // Enforce tree capacity before debiting (fail early without touching balance).
            let count = CommitmentCount::<T>::get();
            let max = T::MaxCommitments::get() as u64;
            ensure!(count < max, Error::<T>::TreeFull);

            // Burn transparent balance.  ExistenceRequirement::AllowDeath permits the caller
            // to shield their entire balance (account may be reaped).
            // The returned NegativeImbalance is dropped here, which reduces TotalIssuance
            // by exactly `amount` — the transparent-to-shielded supply transfer.
            let _burned = T::Currency::withdraw(
                &who,
                amount,
                WithdrawReasons::TRANSFER,
                ExistenceRequirement::AllowDeath,
            )
            .map_err(|_| Error::<T>::InsufficientBalance)?;

            // Compute cm = Poseidon_t5(owner_pubkey, amount_u64, NATIVE_ASSET_ID, blinding).
            // Identical to Note::commitment() in circuits/transfer/src/lib.rs.
            let cm = zc_crypto::commitment::note_commitment(
                &owner_pubkey,
                amount_u64,
                &NATIVE_ASSET_ID,
                &blinding,
            );

            // Append to commitment tree.
            Commitments::<T>::insert(count, cm);
            CommitmentCount::<T>::put(count.saturating_add(1));

            Self::deposit_event(Event::CommitmentInserted { index: count, commitment: cm });
            Self::deposit_event(Event::Shielded { commitment: cm, amount });

            Ok(())
        }

        /// set merkle root. sudo only.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn update_merkle_root(
            origin: OriginFor<T>,
            root: Hash256,
        ) -> DispatchResult {
            ensure_root(origin)?;
            Self::record_merkle_root(root);
            Self::deposit_event(Event::MerkleRootUpdated { root });
            Ok(())
        }
    }

    // -- internal --

    impl<T: Config> Pallet<T> {
        fn do_process_transfer(inputs: &TransferPublicInputs) -> DispatchResult {
            // Count only non-dummy nullifiers and commitments.
            let real_nullifiers: alloc::vec::Vec<&Hash256> = inputs.nullifiers.iter()
                .filter(|n| *n != &DUMMY_FIELD_ELEMENT)
                .collect();
            let real_commitments: alloc::vec::Vec<&Hash256> = inputs.output_commitments.iter()
                .filter(|c| *c != &DUMMY_FIELD_ELEMENT)
                .collect();

            ensure!(real_nullifiers.len() <= MAX_INPUTS as usize, Error::<T>::TooManyNullifiers);
            ensure!(real_commitments.len() <= MAX_OUTPUTS as usize, Error::<T>::TooManyCommitments);

            // Merkle root must be set (no bootstrap bypass).
            ensure!(Self::is_valid_merkle_root(&inputs.merkle_root), Error::<T>::InvalidMerkleRoot);

            // Check no double spends.
            for nullifier in &real_nullifiers {
                ensure!(!NullifierSet::<T>::contains_key(nullifier), Error::<T>::NullifierAlreadySpent);
            }

            // Enforce commitment tree capacity.
            let count = CommitmentCount::<T>::get();
            let max = T::MaxCommitments::get() as u64;
            ensure!(count.saturating_add(real_commitments.len() as u64) <= max, Error::<T>::TreeFull);

            // Mark nullifiers spent.
            let block_number = <frame_system::Pallet<T>>::block_number();
            for nullifier in &real_nullifiers {
                NullifierSet::<T>::insert(nullifier, block_number);
            }
            NullifierCount::<T>::mutate(|c| *c = c.saturating_add(real_nullifiers.len() as u64));

            // Append output commitments.
            let mut idx = count;
            for commitment in &real_commitments {
                Commitments::<T>::insert(idx, commitment);
                Self::deposit_event(Event::CommitmentInserted { index: idx, commitment: **commitment });
                idx = idx.saturating_add(1);
            }
            CommitmentCount::<T>::put(idx);

            TransferCount::<T>::mutate(|c| *c = c.saturating_add(1));
            Self::deposit_event(Event::ShieldedTransferProcessed {
                nullifiers_added: real_nullifiers.len() as u32,
                commitments_added: real_commitments.len() as u32,
                asset_id: inputs.asset_id,
            });

            Ok(())
        }

        fn record_merkle_root(root: Hash256) {
            let history_size = T::MerkleRootHistory::get();
            if history_size > 0 {
                let idx = MerkleRootIndex::<T>::get();
                MerkleRoots::<T>::insert(idx, root);
                MerkleRootIndex::<T>::put((idx + 1) % history_size);
            }
            CurrentMerkleRoot::<T>::put(root);
        }

        fn is_valid_merkle_root(root: &Hash256) -> bool {
            if let Some(current) = CurrentMerkleRoot::<T>::get() {
                if &current == root { return true; }
            } else {
                return false;
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
        fn process_verified_transfer(inputs: &TransferPublicInputs) -> sp_runtime::DispatchResult {
            Self::do_process_transfer(inputs)
        }
    }

    #[cfg(test)]
    impl<T: Config> Pallet<T> {
        pub fn do_process_transfer_pub(inputs: &TransferPublicInputs) -> DispatchResult {
            Self::do_process_transfer(inputs)
        }
    }
}
