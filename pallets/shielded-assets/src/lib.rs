//! # Pallet Shielded Assets
//!
//! Manages private token transfers on Zero Chain.
//!
//! This pallet owns two critical data structures:
//!
//! 1. The **Commitment Tree**: an append-only list of note commitments.
//!    When a shielded transfer is verified, the new output commitments
//!    are appended here. The prover uses this tree to generate Merkle
//!    membership proofs for input notes.
//!
//! 2. The **Nullifier Set**: a set of spent note identifiers. When a
//!    note is spent, its nullifier is added here. If someone tries to
//!    spend the same note again, the nullifier already exists and the
//!    transaction is rejected. This prevents double-spending.
//!
//! The pallet does NOT do proof verification itself. That is handled
//! by pallet-proof-verifier. This pallet is called after verification
//! succeeds, to update the on-chain state.
//!
//! ## Design note on the Merkle tree
//!
//! In production, the commitment tree would be a proper Poseidon Merkle
//! tree computed on-chain. For the prototype, we store commitments in a
//! flat list and track recent Merkle roots that the prover computed
//! off-chain. The prover includes the Merkle root in the public inputs,
//! and this pallet checks that root against the stored list of valid roots.
//! This avoids putting Poseidon hashing inside the WASM runtime for now.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use zk_types::{AssetId, Hash256, TransferPublicInputs, MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID};

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Maximum number of commitments the tree can hold.
        /// 2^20 = ~1 million for prototype. Production uses 2^32.
        #[pallet::constant]
        type MaxCommitments: Get<u32>;

        /// How many recent Merkle roots to keep as valid.
        /// The prover might generate a proof against a root that is a few
        /// blocks old. We keep the last N roots so slightly stale proofs
        /// still work.
        #[pallet::constant]
        type MerkleRootHistory: Get<u32>;
    }

    // ---------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------

    /// All note commitments, in insertion order.
    /// This is the leaf set of the commitment Merkle tree.
    /// Append-only. Never modified or deleted.
    #[pallet::storage]
    #[pallet::getter(fn commitments)]
    pub type Commitments<T: Config> =
        StorageMap<_, Blake2_128Concat, u64, Hash256, OptionQuery>;

    /// Total number of commitments inserted.
    /// Also serves as the next insertion index.
    #[pallet::storage]
    #[pallet::getter(fn commitment_count)]
    pub type CommitmentCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Set of spent nullifiers. If a nullifier exists here, the
    /// corresponding note has been spent and cannot be spent again.
    #[pallet::storage]
    #[pallet::getter(fn nullifier_exists)]
    pub type NullifierSet<T: Config> =
        StorageMap<_, Blake2_128Concat, Hash256, BlockNumberFor<T>, OptionQuery>;

    /// Total number of nullifiers (spent notes).
    #[pallet::storage]
    #[pallet::getter(fn nullifier_count)]
    pub type NullifierCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Recent valid Merkle roots. The prover computes the root off-chain
    /// and includes it in the public inputs. We check it against this list.
    /// Stored as a ring buffer indexed by insertion order.
    #[pallet::storage]
    #[pallet::getter(fn merkle_roots)]
    pub type MerkleRoots<T: Config> =
        StorageMap<_, Blake2_128Concat, u32, Hash256, OptionQuery>;

    /// Index for the next Merkle root insertion (ring buffer pointer).
    #[pallet::storage]
    #[pallet::getter(fn merkle_root_index)]
    pub type MerkleRootIndex<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// The current (latest) Merkle root.
    #[pallet::storage]
    #[pallet::getter(fn current_merkle_root)]
    pub type CurrentMerkleRoot<T: Config> = StorageValue<_, Hash256, OptionQuery>;

    /// Total number of shielded transfers processed.
    #[pallet::storage]
    #[pallet::getter(fn transfer_count)]
    pub type TransferCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    // ---------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A shielded transfer was processed successfully.
        ShieldedTransferProcessed {
            /// Number of notes spent (nullifiers added).
            nullifiers_added: u32,
            /// Number of new notes created (commitments added).
            commitments_added: u32,
            /// The asset type transferred.
            asset_id: AssetId,
        },

        /// A new Merkle root was registered.
        MerkleRootUpdated {
            root: Hash256,
        },

        /// A commitment was added to the tree.
        CommitmentInserted {
            index: u64,
            commitment: Hash256,
        },
    }

    // ---------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        /// A nullifier in the transaction already exists. This note
        /// has already been spent. Double-spend attempt.
        NullifierAlreadySpent,

        /// The Merkle root in the proof does not match any recent
        /// valid root. The proof was generated against a stale or
        /// invalid tree state.
        InvalidMerkleRoot,

        /// Too many nullifiers in the transaction.
        TooManyNullifiers,

        /// Too many output commitments in the transaction.
        TooManyCommitments,

        /// The commitment tree is full.
        TreeFull,

        /// No Merkle root has been set yet. Need at least one
        /// commitment before transfers can be processed.
        NoMerkleRoot,
    }

    // ---------------------------------------------------------------
    // Extrinsics
    // ---------------------------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Process a verified shielded transfer.
        ///
        /// This should be called AFTER pallet-proof-verifier has verified
        /// the Groth16 proof. It does not re-verify the proof. It only
        /// updates the on-chain state: marks nullifiers as spent and
        /// appends new commitments.
        ///
        /// In production, this will be called internally by
        /// pallet-proof-verifier after successful verification.
        /// For the prototype, it is a separate extrinsic so we can
        /// test the state management independently.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(50_000_000, 0))]
        pub fn process_transfer(
            origin: OriginFor<T>,
            inputs: TransferPublicInputs,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // Bounds checks
            ensure!(
                inputs.nullifiers.len() <= MAX_INPUTS as usize,
                Error::<T>::TooManyNullifiers
            );
            ensure!(
                inputs.output_commitments.len() <= MAX_OUTPUTS as usize,
                Error::<T>::TooManyCommitments
            );

            // Check Merkle root is valid (skip if no root set yet, for bootstrapping)
            if CurrentMerkleRoot::<T>::get().is_some() {
                ensure!(
                    Self::is_valid_merkle_root(&inputs.merkle_root),
                    Error::<T>::InvalidMerkleRoot
                );
            }

            // Check none of the nullifiers have been spent
            for nullifier in &inputs.nullifiers {
                ensure!(
                    !NullifierSet::<T>::contains_key(nullifier),
                    Error::<T>::NullifierAlreadySpent
                );
            }

            // All checks passed. Now update state.

            // Mark nullifiers as spent
            let block_number = <frame_system::Pallet<T>>::block_number();
            for nullifier in &inputs.nullifiers {
                NullifierSet::<T>::insert(nullifier, block_number);
            }
            NullifierCount::<T>::mutate(|c| {
                *c = c.saturating_add(inputs.nullifiers.len() as u64)
            });

            // Append output commitments to the tree
            let mut count = CommitmentCount::<T>::get();
            for commitment in &inputs.output_commitments {
                Commitments::<T>::insert(count, commitment);

                Self::deposit_event(Event::CommitmentInserted {
                    index: count,
                    commitment: *commitment,
                });

                count = count.saturating_add(1);
            }
            CommitmentCount::<T>::put(count);

            // Track transfer count
            TransferCount::<T>::mutate(|c| *c = c.saturating_add(1));

            Self::deposit_event(Event::ShieldedTransferProcessed {
                nullifiers_added: inputs.nullifiers.len() as u32,
                commitments_added: inputs.output_commitments.len() as u32,
                asset_id: inputs.asset_id,
            });

            Ok(())
        }

        /// Register a new Merkle root.
        ///
        /// In production, this will be computed on-chain using Poseidon.
        /// For the prototype, the prover computes it off-chain and
        /// submits it. Root only. This is a privileged call (sudo/root).
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn update_merkle_root(
            origin: OriginFor<T>,
            root: Hash256,
        ) -> DispatchResult {
            ensure_root(origin)?;

            // Store in ring buffer
            let history_size = T::MerkleRootHistory::get();
            let idx = MerkleRootIndex::<T>::get();
            MerkleRoots::<T>::insert(idx, root);
            MerkleRootIndex::<T>::put((idx + 1) % history_size);

            // Update current root
            CurrentMerkleRoot::<T>::put(root);

            Self::deposit_event(Event::MerkleRootUpdated { root });

            Ok(())
        }
    }

    // ---------------------------------------------------------------
    // Internal functions
    // ---------------------------------------------------------------

    impl<T: Config> Pallet<T> {
        /// Check if a Merkle root is in the recent valid roots list.
        fn is_valid_merkle_root(root: &Hash256) -> bool {
            // Check current root first (fast path)
            if let Some(current) = CurrentMerkleRoot::<T>::get() {
                if &current == root {
                    return true;
                }
            }

            // Check historical roots
            let history_size = T::MerkleRootHistory::get();
            for i in 0..history_size {
                if let Some(stored_root) = MerkleRoots::<T>::get(i) {
                    if &stored_root == root {
                        return true;
                    }
                }
            }

            false
        }
    }
}
