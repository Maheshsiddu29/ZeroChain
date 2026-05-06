//! shared types for zerochain zk pallets and circuits

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

pub const MAX_INPUTS: u32 = 8;
pub const MAX_OUTPUTS: u32 = 8;
pub const COMMITMENT_TREE_DEPTH: u32 = 32;
pub const VALIDATOR_TREE_DEPTH: u32 = 20;

// bn254 uncompressed point sizes
pub const G1_UNCOMPRESSED_SIZE: usize = 64;  // two 32-byte field elements
pub const G2_UNCOMPRESSED_SIZE: usize = 128; // two 64-byte field elements

pub type Hash256 = [u8; 32];
pub type AssetId = [u8; 32];

/// implemented by pallet-shielded-assets, called by pallet-proof-verifier
/// after groth16 verification passes. lives here to avoid circular deps.
pub trait ShieldedTransferHandler {
    fn process_verified_transfer(inputs: &TransferPublicInputs);
}

/// implemented by pallet-zk-staking, called by pallet-proof-verifier
/// after slashing fraud proof verification passes.
pub trait StakingHandler {
    fn process_slash(inputs: &SlashingPublicInputs);
}

//  groth16 proof (bn254, uncompressed, 256 bytes total)

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen)]
pub struct Groth16Proof {
    pub a: [u8; G1_UNCOMPRESSED_SIZE],
    pub b: [u8; G2_UNCOMPRESSED_SIZE],
    pub c: [u8; G1_UNCOMPRESSED_SIZE],
}

//  halo2 proof (variable size, typically 1-5kb)

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct Halo2Proof {
    pub proof_bytes: Vec<u8>,
}

//  nova proof (zk-origin state lineage)

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct NovaProof {
    pub accumulator: Vec<u8>,
    pub block_height: u64,
}

//  public inputs for shielded transfers
// order must match the circuit: merkle_root, nullifiers, commitments, asset_id, fee

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct TransferPublicInputs {
    pub merkle_root: Hash256,
    pub nullifiers: Vec<Hash256>,
    pub output_commitments: Vec<Hash256>,
    pub asset_id: AssetId,
    pub fee_commitment: Hash256,
}

//  public inputs for validator membership proofs

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct MembershipPublicInputs {
    pub validator_root: Hash256,
    pub epoch: u64,
    pub slot: u64,
}

//  public inputs for zk-origin state lineage

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct OriginPublicInputs {
    pub prev_state_root: Hash256,
    pub new_state_root: Hash256,
    pub block_height: u64,
    pub genesis_hash: Hash256,
    pub num_steps: u64,
}

//  public inputs for equivocation slashing proofs

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct SlashingPublicInputs {
    pub validator_root: Hash256,
    pub nullifier: Hash256,
    pub block_hash_1: Hash256,
    pub block_hash_2: Hash256,
}

//  on-chain verifying keys

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub enum VerifyingKey {
    Groth16(Vec<u8>),
    Halo2(Vec<u8>),
    Nova(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub struct ShieldedTransferData {
    pub proof: Groth16Proof,
    pub inputs: TransferPublicInputs,
}

//  proof submission envelope (what the extrinsic receives)

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo)]
pub enum ProofSubmission {
    ShieldedTransfer(Box<ShieldedTransferData>),
    ValidatorMembership {
        proof: Halo2Proof,
        inputs: MembershipPublicInputs,
    },
    StateLineage {
        proof: NovaProof,
        inputs: OriginPublicInputs,
    },
    Slashing {
        proof: Groth16Proof,
        inputs: SlashingPublicInputs,
    },
}

//  proof type tag for storage key lookups

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen)]
pub enum ProofType {
    Groth16Transfer,
    Halo2Membership,
    NovaOrigin,
    Groth16Slashing,
}

pub const NATIVE_ASSET_ID: AssetId = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Decode, Encode};

    #[test]
    fn groth16_proof_round_trip() {
        let proof = Groth16Proof {
            a: [1u8; G1_UNCOMPRESSED_SIZE],
            b: [2u8; G2_UNCOMPRESSED_SIZE],
            c: [3u8; G1_UNCOMPRESSED_SIZE],
        };
        let encoded = proof.encode();
        let decoded = Groth16Proof::decode(&mut &encoded[..]).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn groth16_proof_size_is_256_bytes() {
        let proof = Groth16Proof {
            a: [0u8; G1_UNCOMPRESSED_SIZE],
            b: [0u8; G2_UNCOMPRESSED_SIZE],
            c: [0u8; G1_UNCOMPRESSED_SIZE],
        };
        let encoded = proof.encode();
        assert_eq!(encoded.len(), 256);
    }

    #[test]
    fn transfer_public_inputs_round_trip() {
        let inputs = TransferPublicInputs {
            merkle_root: [0xAA; 32],
            nullifiers: vec![[0xBB; 32], [0xCC; 32]],
            output_commitments: vec![[0xDD; 32], [0xEE; 32]],
            asset_id: NATIVE_ASSET_ID,
            fee_commitment: [0xFF; 32],
        };
        let encoded = inputs.encode();
        let decoded = TransferPublicInputs::decode(&mut &encoded[..]).unwrap();
        assert_eq!(inputs, decoded);
    }

    #[test]
    fn proof_submission_dispatch_variant() {
        let submission = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
            proof: Groth16Proof {
                a: [1u8; G1_UNCOMPRESSED_SIZE],
                b: [2u8; G2_UNCOMPRESSED_SIZE],
                c: [3u8; G1_UNCOMPRESSED_SIZE],
            },
            inputs: TransferPublicInputs {
                merkle_root: [0xAA; 32],
                nullifiers: vec![[0xBB; 32]],
                output_commitments: vec![[0xCC; 32]],
                asset_id: NATIVE_ASSET_ID,
                fee_commitment: [0xFF; 32],
            },
        }));
        let encoded = submission.encode();
        let decoded = ProofSubmission::decode(&mut &encoded[..]).unwrap();
        assert_eq!(submission, decoded);

        match decoded {
            ProofSubmission::ShieldedTransfer(data) => {
                assert_eq!(data.proof.a[0], 1);
                assert_eq!(data.inputs.nullifiers.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn membership_public_inputs_round_trip() {
        let inputs = MembershipPublicInputs {
            validator_root: [0x11; 32],
            epoch: 42,
            slot: 100,
        };
        let encoded = inputs.encode();
        let decoded = MembershipPublicInputs::decode(&mut &encoded[..]).unwrap();
        assert_eq!(inputs, decoded);
    }

    #[test]
    fn origin_public_inputs_round_trip() {
        let inputs = OriginPublicInputs {
            prev_state_root: [0x22; 32],
            new_state_root: [0x33; 32],
            block_height: 1000,
            genesis_hash: [0x00; 32],
            num_steps: 100,
        };
        let encoded = inputs.encode();
        let decoded = OriginPublicInputs::decode(&mut &encoded[..]).unwrap();
        assert_eq!(inputs, decoded);
    }

    #[test]
    fn slashing_public_inputs_round_trip() {
        let inputs = SlashingPublicInputs {
            validator_root: [0x11; 32],
            nullifier: [0x22; 32],
            block_hash_1: [0x33; 32],
            block_hash_2: [0x44; 32],
        };
        let encoded = inputs.encode();
        let decoded = SlashingPublicInputs::decode(&mut &encoded[..]).unwrap();
        assert_eq!(inputs, decoded);
    }

    #[test]
    fn verifying_key_enum_round_trip() {
        let vk = VerifyingKey::Groth16(vec![1, 2, 3, 4, 5]);
        let encoded = vk.encode();
        let decoded = VerifyingKey::decode(&mut &encoded[..]).unwrap();
        assert_eq!(vk, decoded);
    }

    #[test]
    fn proof_type_max_encoded_len() {
        assert_eq!(ProofType::max_encoded_len(), 1);
    }

    #[test]
    fn native_asset_id_is_all_zeros() {
        assert_eq!(NATIVE_ASSET_ID, [0u8; 32]);
    }
}