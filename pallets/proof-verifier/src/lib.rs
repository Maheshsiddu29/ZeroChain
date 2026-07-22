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
        Groth16Proof, Hash256, ProofSubmission, ProofType, TransferPublicInputs,
        ShieldedTransferHandler,
        MAX_INPUTS, MAX_OUTPUTS,
    };
    #[cfg(feature = "experimental")]
    use zk_types::{Halo2Proof, MembershipPublicInputs, NovaProof, OriginPublicInputs};

    #[cfg(feature = "std")]
    use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
    #[cfg(feature = "std")]
    use ark_groth16::{Groth16, Proof, VerifyingKey as ArkVerifyingKey};
    #[cfg(feature = "std")]
    use ark_serialize::CanonicalDeserialize;
    #[cfg(feature = "std")]
    use ark_snark::SNARK;

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

    // -- genesis --

    /// Seeds the Groth16Transfer verifying key at genesis so every node starts with
    /// the same on-chain VK without a separate sudo transaction.  Passing `None`
    /// leaves the key unset (dev/local presets that test proof submission manually).
    ///
    /// V-03: single-party setup is acceptable for testnet; MPC ceremony required
    /// before mainnet.
    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        pub initial_groth16_transfer_vk: Option<alloc::vec::Vec<u8>>,
        #[serde(skip)]
        pub _phantom: core::marker::PhantomData<T>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            if let Some(ref vk_bytes) = self.initial_groth16_transfer_vk {
                let bounded: BoundedVec<u8, T::MaxVerifyingKeySize> = vk_bytes
                    .clone()
                    .try_into()
                    .expect("genesis VK must fit within MaxVerifyingKeySize (50 KiB)");
                VerifyingKeys::<T>::insert(ProofType::Groth16Transfer, bounded);
            }
        }
    }

    #[pallet::storage]
    #[pallet::getter(fn proof_count_by_type)]
    pub type ProofCountByType<T: Config> =
        StorageMap<_, Blake2_128Concat, ProofType, u64, ValueQuery>;

    /// Encrypted note memos keyed by output commitment.
    /// Written after Groth16 verification succeeds; never part of the verified computation.
    /// Each value: X25519_ephemeral_pk(32) || nonce(12) || ChaCha20Poly1305_ct(96) = 140 bytes.
    #[pallet::storage]
    pub type NoteMemos<T: Config> = StorageMap<
        _, Blake2_128Concat, Hash256,
        BoundedVec<u8, frame_support::traits::ConstU32<256>>, OptionQuery
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ProofVerified { submitter: T::AccountId, proof_type: ProofType },
        ProofRejected { submitter: T::AccountId, proof_type: ProofType },
        VerifyingKeyUpdated { proof_type: ProofType },
        /// Emitted when a note memo is stored (post-verification, not part of proof).
        MemoAttached { commitment: Hash256 },
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
        /// A public input field element is not in canonical form (>= BN254 order).
        /// This closes the n+r double-spend encoding attack (C-01/H-13).
        InvalidPublicInput,
        /// Proof type is not supported in this build. ValidatorMembership, StateLineage,
        /// and Slashing require the "experimental" feature flag and are absent from the
        /// production runtime. Only ShieldedTransfer is accepted in production.
        UnsupportedProofType,
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
                    // Verification: proof and inputs only — memos are never seen here.
                    Self::verify_shielded_transfer(&data.proof, &data.inputs)?;
                    ProofCount::<T>::mutate(|c| *c = c.saturating_add(1));
                    ProofCountByType::<T>::mutate(ProofType::Groth16Transfer, |c| *c = c.saturating_add(1));
                    Self::deposit_event(Event::ProofVerified { submitter, proof_type: ProofType::Groth16Transfer });

                    // Post-verification: store encrypted memos keyed by output commitment.
                    // Indexed by position so memo[i] corresponds to output_commitments[i].
                    for (commitment, memo_bytes) in data.inputs.output_commitments.iter()
                        .zip(data.memos.iter())
                    {
                        // [0u8;32] is the DUMMY_FIELD_ELEMENT sentinel for unused output slots.
                        if *commitment == [0u8; 32] || memo_bytes.is_empty() { continue; }
                        if let Ok(bounded) = BoundedVec::<u8, frame_support::traits::ConstU32<256>>::try_from(memo_bytes.clone()) {
                            NoteMemos::<T>::insert(commitment, bounded);
                            Self::deposit_event(Event::MemoAttached { commitment: *commitment });
                        }
                    }
                }
                // Experimental proof types — stub verifiers, not production-safe.
                // Absent from the production runtime; only reachable with --features experimental.
                #[cfg(feature = "experimental")]
                ProofSubmission::ValidatorMembership { proof, inputs } => {
                    Self::verify_validator_membership(&proof, &inputs)?;
                    ProofCount::<T>::mutate(|c| *c = c.saturating_add(1));
                    ProofCountByType::<T>::mutate(ProofType::Halo2Membership, |c| *c = c.saturating_add(1));
                    Self::deposit_event(Event::ProofVerified { submitter, proof_type: ProofType::Halo2Membership });
                }
                #[cfg(feature = "experimental")]
                ProofSubmission::StateLineage { proof, inputs } => {
                    Self::verify_state_lineage(&proof, &inputs)?;
                    ProofCount::<T>::mutate(|c| *c = c.saturating_add(1));
                    ProofCountByType::<T>::mutate(ProofType::NovaOrigin, |c| *c = c.saturating_add(1));
                    Self::deposit_event(Event::ProofVerified { submitter, proof_type: ProofType::NovaOrigin });
                }
                #[cfg(feature = "experimental")]
                ProofSubmission::Slashing { proof, inputs } => {
                    ensure!(!proof.a.is_empty(), Error::<T>::InvalidProofFormat);
                    let _ = inputs;
                    ProofCount::<T>::mutate(|c| *c = c.saturating_add(1));
                    ProofCountByType::<T>::mutate(ProofType::Groth16Slashing, |c| *c = c.saturating_add(1));
                    Self::deposit_event(Event::ProofVerified { submitter, proof_type: ProofType::Groth16Slashing });
                }
                // Production catch-all: any non-transfer variant is unsupported.
                #[cfg(not(feature = "experimental"))]
                _ => return Err(Error::<T>::UnsupportedProofType.into()),
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
        /// deserializes proof + vk, builds FIXED-SHAPE public input vector, runs pairing check.
        fn verify_shielded_transfer(
            proof: &Groth16Proof,
            inputs: &TransferPublicInputs,
        ) -> DispatchResult {
            ensure!(inputs.nullifiers.len() <= MAX_INPUTS as usize, Error::<T>::TooManyInputs);
            ensure!(inputs.output_commitments.len() <= MAX_OUTPUTS as usize, Error::<T>::TooManyOutputs);

            Self::do_verify_groth16(proof, inputs)?;

            // proof passed, update shielded state
            T::TransferHandler::process_verified_transfer(inputs)?;
            Ok(())
        }

        /// Native path: real arkworks BN254 Groth16 verification.
        ///
        /// Fixes applied here:
        ///   C-19 — pads nullifiers to MAX_INPUTS and commitments to MAX_OUTPUTS with Fr::zero
        ///          so the public-input vector always has exactly 19 elements to match the
        ///          fixed-shape circuit.
        ///   C-01 / H-13 — uses `Fr::deserialize_uncompressed` (canonical, rejects >= p) instead
        ///          of `from_le_bytes_mod_order` (silently reduces) for every public input.
        ///          G1/G2 proof points use the checked deserializer (subgroup check included).
        #[cfg(feature = "std")]
        fn do_verify_groth16(
            proof: &Groth16Proof,
            inputs: &TransferPublicInputs,
        ) -> DispatchResult {
            let vk_bytes = VerifyingKeys::<T>::get(ProofType::Groth16Transfer)
                .ok_or(Error::<T>::NoVerifyingKey)?;

            // Canonical proof-point deserialization with implicit subgroup check (H-13)
            let a = G1Affine::deserialize_uncompressed(&proof.a[..])
                .map_err(|_| Error::<T>::InvalidProofFormat)?;
            let b = G2Affine::deserialize_uncompressed(&proof.b[..])
                .map_err(|_| Error::<T>::InvalidProofFormat)?;
            let c = G1Affine::deserialize_uncompressed(&proof.c[..])
                .map_err(|_| Error::<T>::InvalidProofFormat)?;
            let ark_proof = Proof::<Bn254> { a, b, c };

            let vk = ArkVerifyingKey::<Bn254>::deserialize_uncompressed(&vk_bytes[..])
                .map_err(|_| Error::<T>::InvalidVerifyingKey)?;

            // Build the FIXED-SHAPE public-input vector (C-19).
            // Total = 1 + MAX_INPUTS + MAX_OUTPUTS + 1 + 1 = 19 elements.
            let mut public_inputs: Vec<Fr> = Vec::with_capacity(1 + MAX_INPUTS as usize + MAX_OUTPUTS as usize + 2);

            let parse = |bytes: &[u8; 32]| -> Result<Fr, Error<T>> {
                Fr::deserialize_uncompressed(&bytes[..])
                    .map_err(|_| Error::<T>::InvalidPublicInput)
            };

            public_inputs.push(parse(&inputs.merkle_root)?);

            // Pad nullifiers to exactly MAX_INPUTS, filling unused slots with Fr::zero (C-19)
            for i in 0..MAX_INPUTS as usize {
                let bytes = inputs.nullifiers.get(i).copied().unwrap_or([0u8; 32]);
                public_inputs.push(parse(&bytes)?);
            }

            // Pad output commitments to exactly MAX_OUTPUTS (C-19)
            for i in 0..MAX_OUTPUTS as usize {
                let bytes = inputs.output_commitments.get(i).copied().unwrap_or([0u8; 32]);
                public_inputs.push(parse(&bytes)?);
            }

            public_inputs.push(parse(&inputs.asset_id)?);
            public_inputs.push(parse(&inputs.fee_commitment)?);

            let pvk = ark_groth16::prepare_verifying_key(&vk);
            let is_valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &ark_proof)
                .map_err(|_| Error::<T>::ProofVerificationFailed)?;
            ensure!(is_valid, Error::<T>::ProofVerificationFailed);
            Ok(())
        }

        /// WASM path: calls the `zc_groth16_io` host function registered in the node executor.
        ///
        /// The host function performs real BN254 pairing verification natively and returns a bool.
        /// Public inputs are serialised as a flat 608-byte array (19 × 32 bytes) padded to the
        /// fixed circuit shape (C-19). Non-canonical encodings are rejected inside the host
        /// function (C-01/H-13).
        #[cfg(not(feature = "std"))]
        fn do_verify_groth16(
            proof: &Groth16Proof,
            inputs: &TransferPublicInputs,
        ) -> DispatchResult {
            use zc_groth16_io::zc_groth_16;

            let vk_bytes = VerifyingKeys::<T>::get(ProofType::Groth16Transfer)
                .ok_or(Error::<T>::NoVerifyingKey)?;

            // Build flat public-input buffer: 19 × 32 bytes (C-19)
            let mut flat: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(19 * 32);
            flat.extend_from_slice(&inputs.merkle_root);
            for i in 0..MAX_INPUTS as usize {
                let bytes = inputs.nullifiers.get(i).copied().unwrap_or([0u8; 32]);
                flat.extend_from_slice(&bytes);
            }
            for i in 0..MAX_OUTPUTS as usize {
                let bytes = inputs.output_commitments.get(i).copied().unwrap_or([0u8; 32]);
                flat.extend_from_slice(&bytes);
            }
            flat.extend_from_slice(&inputs.asset_id);
            flat.extend_from_slice(&inputs.fee_commitment);

            // Pack into the format expected by verify_bn254
            let request = zc_groth16_io::pack_request(
                &proof.a,
                &proof.b,
                &proof.c,
                &vk_bytes,
                &flat,
            );

            let is_valid = zc_groth_16::verify_bn254(&request);
            ensure!(is_valid, Error::<T>::ProofVerificationFailed);
            Ok(())
        }

        #[cfg(feature = "experimental")]
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

        #[cfg(feature = "experimental")]
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
