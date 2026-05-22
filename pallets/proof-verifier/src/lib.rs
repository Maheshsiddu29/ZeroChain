//! Proof Verifier Pallet - Updated to use real verification

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_io::hashing::blake2_256;
    
    // Import from host functions
    use zc_host_functions::{Groth16Verifier, Halo2Verifier, NovaVerifier};

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Groth16 proof verified
        Groth16Verified { commitment: [u8; 32] },
        /// Halo2 proof verified
        Halo2Verified { root: [u8; 32] },
        /// Nova proof verified
        NovaVerified { genesis: [u8; 32], final_root: [u8; 32] },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// Proof verification failed
        ProofVerificationFailed,
        /// Invalid proof format
        InvalidProofFormat,
        /// Invalid public inputs
        InvalidPublicInputs,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Verify Groth16 transfer proof
        #[pallet::call_index(0)]
        #[pallet::weight(100_000)]
        pub fn verify_groth16(
            origin: OriginFor<T>,
            proof: Vec<u8>,
            commitment: [u8; 32],
            nullifier: [u8; 32],
            amount: u128,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // Call host function
            let verified = Groth16Verifier::verify_transfer(
                &proof,
                commitment,
                nullifier,
                amount,
            );

            ensure!(verified, Error::<T>::ProofVerificationFailed);

            Self::deposit_event(Event::Groth16Verified { commitment });
            Ok(())
        }

        /// Verify Halo2 membership proof
        #[pallet::call_index(1)]
        #[pallet::weight(150_000)]
        pub fn verify_halo2_membership(
            origin: OriginFor<T>,
            proof: Vec<u8>,
            commitment: [u8; 32],
            tree_root: [u8; 32],
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // Call host function
            let verified = Halo2Verifier::verify_membership(
                &proof,
                commitment,
                tree_root,
                20, // depth
            );

            ensure!(verified, Error::<T>::ProofVerificationFailed);

            Self::deposit_event(Event::Halo2Verified { root: tree_root });
            Ok(())
        }

        /// Verify Nova state lineage proof
        #[pallet::call_index(2)]
        #[pallet::weight(200_000)]
        pub fn verify_state_lineage(
            origin: OriginFor<T>,
            proof: Vec<u8>,
            genesis_root: [u8; 32],
            final_root: [u8; 32],
            num_steps: u64,
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // Validate proof size
            ensure!(
                proof.len() >= 64 && proof.len() <= 10000,
                Error::<T>::InvalidProofFormat
            );

            // Extract accumulator
            let accumulator = &proof[64..];

            // Call host function
            let verified = NovaVerifier::verify(
                accumulator,
                &[], // VK
                genesis_root,
                final_root,
                num_steps,
            );

            ensure!(verified, Error::<T>::ProofVerificationFailed);

            // Store lineage proof record
            log::info!(
                "✓ State lineage verified: {} steps from {:?} to {:?}",
                num_steps,
                hex::encode(&genesis_root[..4]),
                hex::encode(&final_root[..4])
            );

            Self::deposit_event(Event::NovaVerified {
                genesis: genesis_root,
                final_root,
            });

            Ok(())
        }

        /// Verify Halo2 slashing proof
        #[pallet::call_index(3)]
        #[pallet::weight(150_000)]
        pub fn verify_slashing_proof(
            origin: OriginFor<T>,
            proof: Vec<u8>,
            validator_root: [u8; 32],
            block_hash_1: [u8; 32],
            block_hash_2: [u8; 32],
        ) -> DispatchResult {
            let _who = ensure_signed(origin)?;

            // Call host function
            let verified = Halo2Verifier::verify_slashing(
                &proof,
                validator_root,
                block_hash_1,
                block_hash_2,
            );

            ensure!(verified, Error::<T>::ProofVerificationFailed);

            log::info!("✓ Slashing proof verified");

            Ok(())
        }
    }

    // Storage and other implementations...
    impl<T: Config> Pallet<T> {
        pub fn verify_transfer(
            proof: &[u8],
            commitment: [u8; 32],
            nullifier: [u8; 32],
            amount: u128,
        ) -> bool {
            Groth16Verifier::verify_transfer(proof, commitment, nullifier, amount)
        }

        pub fn verify_membership(
            proof: &[u8],
            commitment: [u8; 32],
            root: [u8; 32],
        ) -> bool {
            Halo2Verifier::verify_membership(proof, commitment, root, 20)
        }

        pub fn verify_lineage(
            proof: &[u8],
            genesis: [u8; 32],
            final_root: [u8; 32],
            steps: u64,
        ) -> bool {
            let accumulator = if proof.len() > 64 {
                &proof[64..]
            } else {
                &[]
            };
            NovaVerifier::verify(accumulator, &[], genesis, final_root, steps)
        }
    }
}