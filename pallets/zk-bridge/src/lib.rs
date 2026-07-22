//! cross-chain bridge with zk-origin proofs for zerochain.
//! verifies that bridge messages genuinely originated from
//! the claimed source chain using cryptographic origin proofs.
//! no trusted bridge operators required.
//!
//! **EXPERIMENTAL — not security-audited, disabled in production builds.**
//! Enable with `--features experimental` for research and testing only.

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
    use zk_types::{Hash256, BridgeMessage, BridgeOriginInputs};

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// maximum number of registered source chains
        #[pallet::constant]
        type MaxSourceChains: Get<u32>;

        /// maximum payload size in bytes
        #[pallet::constant]
        type MaxPayloadSize: Get<u32>;
    }

    // -- storage --

    /// registered source chain state roots.
    /// maps source_chain_id -> latest known state root.
    /// updated by relayers with origin proofs.
    #[pallet::storage]
    #[pallet::getter(fn origin_root)]
    pub type OriginRoots<T: Config> =
        StorageMap<_, Blake2_128Concat, u32, Hash256, OptionQuery>;

    /// processed message nonces per source chain.
    /// prevents replay attacks.
    #[pallet::storage]
    #[pallet::getter(fn processed_nonce)]
    pub type ProcessedNonces<T: Config> =
        StorageMap<_, Blake2_128Concat, u32, u64, ValueQuery>;

    /// processed message hashes.
    /// maps message_hash -> block number when processed.
    #[pallet::storage]
    #[pallet::getter(fn is_processed)]
    pub type ProcessedMessages<T: Config> =
        StorageMap<_, Blake2_128Concat, Hash256, BlockNumberFor<T>, OptionQuery>;

    /// total messages processed across all chains
    #[pallet::storage]
    #[pallet::getter(fn message_count)]
    pub type MessageCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// total registered source chains
    #[pallet::storage]
    #[pallet::getter(fn chain_count)]
    pub type ChainCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    // -- events --

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// new source chain registered with initial state root
        SourceChainRegistered { chain_id: u32, state_root: Hash256 },
        /// source chain state root updated via origin proof
        OriginRootUpdated { chain_id: u32, new_root: Hash256 },
        /// bridge message verified and processed
        MessageProcessed {
            source_chain_id: u32,
            message_hash: Hash256,
            nonce: u64,
        },
        /// message rejected (replay, invalid origin, etc)
        MessageRejected {
            source_chain_id: u32,
            message_hash: Hash256,
            reason: RejectReason,
        },
    }

    #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
    pub enum RejectReason {
        UnknownSourceChain,
        NonceAlreadyProcessed,
        MessageAlreadyProcessed,
        OriginRootMismatch,
        PayloadTooLarge,
    }

    // -- errors --

    #[pallet::error]
    pub enum Error<T> {
        /// source chain not registered
        UnknownSourceChain,
        /// message nonce already processed (replay attack)
        NonceAlreadyProcessed,
        /// message hash already processed (duplicate)
        MessageAlreadyProcessed,
        /// origin state root does not match registered root
        OriginRootMismatch,
        /// message payload exceeds maximum size
        PayloadTooLarge,
        /// maximum number of source chains reached
        TooManySourceChains,
        /// source chain already registered
        ChainAlreadyRegistered,
        /// nonce must be sequential
        NonceOutOfOrder,
    }

    // -- extrinsics --

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// register a new source chain with its initial state root.
        /// sudo only for prototype. in production, this would require
        /// a governance vote or a verified genesis proof.
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn register_source_chain(
            origin: OriginFor<T>,
            chain_id: u32,
            initial_state_root: Hash256,
        ) -> DispatchResult {
            ensure_root(origin)?;

            let count = ChainCount::<T>::get();
            ensure!(count < T::MaxSourceChains::get(), Error::<T>::TooManySourceChains);
            ensure!(
                !OriginRoots::<T>::contains_key(chain_id),
                Error::<T>::ChainAlreadyRegistered
            );

            OriginRoots::<T>::insert(chain_id, initial_state_root);
            ChainCount::<T>::mutate(|c| *c = c.saturating_add(1));

            Self::deposit_event(Event::SourceChainRegistered {
                chain_id,
                state_root: initial_state_root,
            });
            Ok(())
        }

        /// update a source chain's state root.
        /// in production, this requires a ZK-ORIGIN proof verifying
        /// the state transition from the old root to the new root.
        /// for prototype, sudo only.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn update_origin_root(
            origin: OriginFor<T>,
            chain_id: u32,
            new_state_root: Hash256,
        ) -> DispatchResult {
            ensure_root(origin)?;

            ensure!(
                OriginRoots::<T>::contains_key(chain_id),
                Error::<T>::UnknownSourceChain
            );

            OriginRoots::<T>::insert(chain_id, new_state_root);

            Self::deposit_event(Event::OriginRootUpdated {
                chain_id,
                new_root: new_state_root,
            });
            Ok(())
        }

        /// submit a bridge message with origin verification.
        /// the message must come from a registered source chain,
        /// the nonce must be sequential, and the origin state root
        /// must match the registered root.
        ///
        /// in production, this is called by proof-verifier after
        /// ZK-ORIGIN proof verification. for prototype, anyone can
        /// submit with direct state root matching.
        #[pallet::call_index(2)]
        #[pallet::weight(Weight::from_parts(20_000_000, 0))]
        pub fn submit_bridge_message(
            origin: OriginFor<T>,
            message: BridgeMessage,
            origin_inputs: BridgeOriginInputs,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // validate payload size
            ensure!(
                message.payload.len() <= T::MaxPayloadSize::get() as usize,
                Error::<T>::PayloadTooLarge
            );

            // validate source chain is registered
            let stored_root = OriginRoots::<T>::get(message.source_chain_id)
                .ok_or(Error::<T>::UnknownSourceChain)?;

            // validate origin state root matches
            ensure!(
                stored_root == origin_inputs.source_state_root,
                Error::<T>::OriginRootMismatch
            );

            // validate chain ids match
            ensure!(
                message.source_chain_id == origin_inputs.source_chain_id,
                Error::<T>::UnknownSourceChain
            );

            // validate message hash matches
            ensure!(
                message.message_hash == origin_inputs.message_hash,
                Error::<T>::OriginRootMismatch
            );

            // check nonce is sequential (prevents replay)
            let current_nonce = ProcessedNonces::<T>::get(message.source_chain_id);
            ensure!(
                message.nonce == current_nonce + 1,
                Error::<T>::NonceOutOfOrder
            );

            // check message not already processed
            ensure!(
                !ProcessedMessages::<T>::contains_key(&message.message_hash),
                Error::<T>::MessageAlreadyProcessed
            );

            // process the message
            let block_number = <frame_system::Pallet<T>>::block_number();
            ProcessedMessages::<T>::insert(&message.message_hash, block_number);
            ProcessedNonces::<T>::insert(message.source_chain_id, message.nonce);
            MessageCount::<T>::mutate(|c| *c = c.saturating_add(1));

            Self::deposit_event(Event::MessageProcessed {
                source_chain_id: message.source_chain_id,
                message_hash: message.message_hash,
                nonce: message.nonce,
            });

            Ok(())
        }
    }

    // -- trait implementation for proof-verifier integration --

    impl<T: Config> zk_types::BridgeHandler for Pallet<T> {
        /// called by proof-verifier after ZK-ORIGIN bridge proof verification.
        /// processes the message if valid, silently skips if already processed.
        fn process_verified_message(message: &BridgeMessage, inputs: &BridgeOriginInputs) {
            // skip if already processed (infallible trait)
            if ProcessedMessages::<T>::contains_key(&message.message_hash) {
                return;
            }

            let block_number = <frame_system::Pallet<T>>::block_number();
            ProcessedMessages::<T>::insert(&message.message_hash, block_number);
            ProcessedNonces::<T>::insert(message.source_chain_id, message.nonce);
            MessageCount::<T>::mutate(|c| *c = c.saturating_add(1));

            Self::deposit_event(Event::MessageProcessed {
                source_chain_id: message.source_chain_id,
                message_hash: message.message_hash,
                nonce: message.nonce,
            });
        }
    }
}