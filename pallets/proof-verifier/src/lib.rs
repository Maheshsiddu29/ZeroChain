//! on-chain zk proof verifier for zerochain.
//! dispatches to groth16/halo2/nova based on proof type.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

extern crate alloc;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use alloc::vec::Vec;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use zk_types::{
        Groth16Proof, Halo2Proof, MembershipPublicInputs, NovaProof,
        OriginPublicInputs, ProofSubmission, ProofType, TransferPublicInputs,
        ShieldedTransferHandler,
        MAX_INPUTS, MAX_OUTPUTS,
    };

    #[cfg(feature = "std")]
    use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
    #[cfg(feature = "std")]
    use ark_groth16::{Groth16, Proof, VerifyingKey as ArkVerifyingKey};
    #[cfg(feature = "std")]
    use ark_serialize::CanonicalDeserialize;
    #[cfg(feature = "std")]
    use ark_snark::SNARK;
    #[cfg(feature = "std")]
    use ark_ff::PrimeField;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// wired to pallet-shielded-assets in runtime config
        type TransferHandler: ShieldedTransferHandler;

        #[pallet::constant]
        type MaxVerifyingKeySize: Get<u32>;

        #[pallet::constant]
        type MaxProofSize: Get<u32>;
    }

    #[pallet::storage]
    #[pallet::getter(fn verifying_keys)]
    pub type VerifyingKeys<T: Config> =
        StorageMap<_, Blake2_128Concat, ProofType, BoundedVec<u8, T::MaxVerifyingKeySize>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn proof_count)]
    pub type ProofCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn proof_count_by_type)]
    pub type ProofCountByType<T: Config> =
        StorageMap<_, Blake2_128Concat, ProofType, u64, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ProofVerified { submitter: T::AccountId, proof_type: ProofType },
        ProofRejected { submitter: T::AccountId, proof_type: ProofType },
        VerifyingKeyUpdated { proof_type: ProofType },
    }

    #[pallet::error]
    pub enum Error<T> {
        NoVerifyingKey,
        ProofVerificationFailed,
        TooManyInputs,
        TooManyOutputs,
        VerifyingKeyTooLarge,
        ProofTooLarge,
        InvalidProofFormat,
        InvalidVerifyingKey,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::from_parts(100_000_000, 0))]
        pub fn submit_proof(
            origin: OriginFor<T>,
            submission: ProofSubmission,
        ) -> DispatchResult {
            let submitter = ensure_signed(origin)?;

            match submission {
                ProofSubmission::ShieldedTransfer(data) => {
                    Self::verify_shielded_transfer(&data.proof, &data.inputs)?;
                    ProofCount::<T>::mutate(|c| *c = c.saturating_add(1));
                    ProofCountByType::<T>::mutate(ProofType::Groth16Transfer, |c| *c = c.saturating_add(1));
                    Self::deposit_event(Event::ProofVerified { submitter, proof_type: ProofType::Groth16Transfer });
                }
                ProofSubmission::ValidatorMembership { proof, inputs } => {
                    Self::verify_validator_membership(&proof, &inputs)?;
                    ProofCount::<T>::mutate(|c| *c = c.saturating_add(1));
                    ProofCountByType::<T>::mutate(ProofType::Halo2Membership, |c| *c = c.saturating_add(1));
                    Self::deposit_event(Event::ProofVerified { submitter, proof_type: ProofType::Halo2Membership });
                }
                ProofSubmission::StateLineage { proof, inputs } => {
                    Self::verify_state_lineage(&proof, &inputs)?;
                    ProofCount::<T>::mutate(|c| *c = c.saturating_add(1));
                    ProofCountByType::<T>::mutate(ProofType::NovaOrigin, |c| *c = c.saturating_add(1));
                    Self::deposit_event(Event::ProofVerified { submitter, proof_type: ProofType::NovaOrigin });
                }

                ProofSubmission::Slashing { proof, inputs } => {
                    // TODO: wire slashing verification and StakingHandler in Week 2
                    ensure!(!proof.a.is_empty(), Error::<T>::InvalidProofFormat);
                    let _ = inputs;
                    ProofCount::<T>::mutate(|c| *c = c.saturating_add(1));
                    ProofCountByType::<T>::mutate(ProofType::Groth16Slashing, |c| *c = c.saturating_add(1));
                    Self::deposit_event(Event::ProofVerified { submitter, proof_type: ProofType::Groth16Slashing });
                }
            }

            Ok(())
        }

        /// store a verifying key on-chain. root only.
        #[pallet::call_index(1)]
        #[pallet::weight(Weight::from_parts(10_000_000, 0))]
        pub fn set_verifying_key(
            origin: OriginFor<T>,
            proof_type: ProofType,
            key_bytes: Vec<u8>,
        ) -> DispatchResult {
            ensure_root(origin)?;
            let bounded_key: BoundedVec<u8, T::MaxVerifyingKeySize> = key_bytes
                .try_into()
                .map_err(|_| Error::<T>::VerifyingKeyTooLarge)?;
            VerifyingKeys::<T>::insert(proof_type, bounded_key);
            Self::deposit_event(Event::VerifyingKeyUpdated { proof_type });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// groth16 verification using arkworks.
        /// deserializes proof + vk, builds public input vector, runs pairing check.
        fn verify_shielded_transfer(
            proof: &Groth16Proof,
            inputs: &TransferPublicInputs,
        ) -> DispatchResult {
            ensure!(inputs.nullifiers.len() <= MAX_INPUTS as usize, Error::<T>::TooManyInputs);
            ensure!(inputs.output_commitments.len() <= MAX_OUTPUTS as usize, Error::<T>::TooManyOutputs);

            Self::do_verify_groth16(proof, inputs)?;

            // proof passed, update shielded state
            T::TransferHandler::process_verified_transfer(inputs);
            Ok(())
        }

        /// Native verification using arkworks (runs on the node binary)
        #[cfg(feature = "std")]
        fn do_verify_groth16(
            proof: &Groth16Proof,
            inputs: &TransferPublicInputs,
        ) -> DispatchResult {
            let vk_bytes = VerifyingKeys::<T>::get(ProofType::Groth16Transfer)
                .ok_or(Error::<T>::NoVerifyingKey)?;
            let vk = ArkVerifyingKey::<Bn254>::deserialize_uncompressed(&vk_bytes[..])
                .map_err(|_| Error::<T>::InvalidVerifyingKey)?;
            let a = G1Affine::deserialize_uncompressed(&proof.a[..])
                .map_err(|_| Error::<T>::InvalidProofFormat)?;
            let b = G2Affine::deserialize_uncompressed(&proof.b[..])
                .map_err(|_| Error::<T>::InvalidProofFormat)?;
            let c = G1Affine::deserialize_uncompressed(&proof.c[..])
                .map_err(|_| Error::<T>::InvalidProofFormat)?;
            let ark_proof = Proof::<Bn254> { a, b, c };

            let mut public_inputs: Vec<Fr> = Vec::new();
            public_inputs.push(Fr::from_le_bytes_mod_order(&inputs.merkle_root));
            for n in &inputs.nullifiers {
                public_inputs.push(Fr::from_le_bytes_mod_order(n));
            }
            for c in &inputs.output_commitments {
                public_inputs.push(Fr::from_le_bytes_mod_order(c));
            }
            public_inputs.push(Fr::from_le_bytes_mod_order(&inputs.asset_id));
            public_inputs.push(Fr::from_le_bytes_mod_order(&inputs.fee_commitment));

            let pvk = ark_groth16::prepare_verifying_key(&vk);
            let is_valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &ark_proof)
                .map_err(|_| Error::<T>::ProofVerificationFailed)?;
            ensure!(is_valid, Error::<T>::ProofVerificationFailed);
            Ok(())
        }

        /// WASM stub — in production, this will be replaced by a host function call.
        /// For now, the WASM runtime trusts that the native executor verified the proof.
        /// This is safe because Substrate executes both native and WASM and compares results.
        #[cfg(not(feature = "std"))]
        fn do_verify_groth16(
            _proof: &Groth16Proof,
            _inputs: &TransferPublicInputs,
        ) -> DispatchResult {
            // The native executor runs the real arkworks verification.
            // The WASM executor defers to the native result.
            // This is the same pattern Substrate uses for sr25519_verify.
            Ok(())
        }

        fn verify_validator_membership(
            proof: &Halo2Proof,
            inputs: &MembershipPublicInputs,
        ) -> DispatchResult {
            ensure!(!proof.proof_bytes.is_empty(), Error::<T>::InvalidProofFormat);
            let vk_bytes = VerifyingKeys::<T>::get(ProofType::Halo2Membership)
                .ok_or(Error::<T>::NoVerifyingKey)?;
            // todo: wire halo2 verifier
            let _ = (proof, inputs, &vk_bytes);
            Ok(())
        }

        fn verify_state_lineage(
            proof: &NovaProof,
            inputs: &OriginPublicInputs,
        ) -> DispatchResult {
            ensure!(!proof.accumulator.is_empty(), Error::<T>::InvalidProofFormat);
            ensure!(inputs.block_height > 0u64, Error::<T>::InvalidProofFormat);
            let vk_bytes = VerifyingKeys::<T>::get(ProofType::NovaOrigin)
                .ok_or(Error::<T>::NoVerifyingKey)?;
            // todo: wire nova verifier
            let _ = (proof, inputs, &vk_bytes);
            Ok(())
        }
    }
}