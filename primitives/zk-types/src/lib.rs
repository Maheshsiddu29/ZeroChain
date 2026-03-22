//! # Zero Chain ZK Types

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;
use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;


pub const MAX_INPUTS: u32 = 8;

//max no of outputs per shield transfer
pub const MAX_OUTPUTS: u32 = 8;


//depth of merkle tree
pub const COMMITMENT_TREE_DEPTH: u32 = 32;


//depth of validator tree depth , ie; total 1 million validators  
pub const VALIDATOR_TREE_DEPTH: u32 = 20;

//byte sizes for eliptic cuves(bn254, here we are considering uncompressed)

//point G1 on BN254 consists of two field elements, 32 bytes each, uncompressed, so total size 64 bytes.
pub const G1_UNCOMPRESSED_SIZE: usize = 64;

//point G2 on BN254 consists of two field elements, 64 bytes each, uncompressed, so total size 128 bytes.
pub const G2_UNCOMPRESSED_SIZE: usize = 128;

//32 byte hash, this hash Used for Poseidon commitments, nullifiers, Merkle roots.
pub type Hash256 = [u8; 32];

//32-byte asset identifier.native ZERO token has a predefined ID.
//Other assets use Hash as their ID.
pub type AssetId = [u8; 32];


//Groth16 Proof 


//Groth16 proof over the BN254 curve, this proof is output by arkworks ark-groth16

//Encoding: uncompressed, using ark-serialize CanonicalSerialize with
//Uncompressed mode. 

//Total size: 64 + 128 + 64 = 256 bytes.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub struct Groth16Proof {
    //G1 point (a), 64 bytes uncompressed.
    pub a: [u8; G1_UNCOMPRESSED_SIZE],
    //G2 point (b), 128 bytes uncompressed.
    pub b: [u8; G2_UNCOMPRESSED_SIZE],
    //G1 point (c), 64 bytes uncompressed.
    pub c: [u8; G1_UNCOMPRESSED_SIZE],
}


//Halo2 Proof (Validator Membership)


//A Halo2 proof for validator set membership.

//Halo2 proof sizes vary by circuit complexity, so this uses a Vec<u8>
//rather than a fixed array. 
//Typical range: 1-5 KB.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct Halo2Proof {
    //Raw serialized Halo2 proof bytes.
    pub proof_bytes: Vec<u8>,
}


//Nova Proof (ZK-ORIGIN State Lineage)


//A Nova IVC (Incrementally Verifiable Computation) proof for ZK-ORIGIN.
//
//Contains the folding accumulator that proves an unbroken chain of valid
//state transitions from genesis to the current block. 
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct NovaProof {
    //The Nova IVC accumulator bytes.
    //Size depends on the circuit but is constant for a given circuit version.
    pub accumulator: Vec<u8>,
    //The block height this proof covers up to.
    pub block_height: u64,
}


//Public Inputs: Shielded Transfer


//Public inputs for a shielded transfer transaction.
//
//These are the values visible to the on-chain verifier. Everything else
//(amounts, sender, receiver) stays hidden inside the ZK proof.
//
//Layout agreement:
//vikram your transfer circuit should exppose these inputs in the exact order 
//-pallet-proof-verifier deserializes them in this exact order
//-The field elements in the circuit map 1:1 to these byte arrays
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct TransferPublicInputs {
    //Root of the note commitment Merkle tree at the time of proof generation.
    //The prover picks a recent root; the verifier checks it matches a known root.
    pub merkle_root: Hash256,

    //Nullifiers for each spent input note. These get added to the NullifierSet
    //on-chain to prevent double-spending. Up to MAX_INPUTS.
    pub nullifiers: Vec<Hash256>,

    //Commitments for each new output note. These get appended to the
    //CommitmentTree on-chain. Up to MAX_OUTPUTS.
    pub output_commitments: Vec<Hash256>,

    //Asset ID for this transfer. For single-asset transfers, all inputs and
    //outputs share the same asset. For cross-asset atomic swaps (future),
    //this will be extended.
    pub asset_id: AssetId,

    //The fee commitment. The proof demonstrates that the fee is at least the
    //minimum required, without revealing the exact fee amount.
    pub fee_commitment: Hash256,
}


//Public Inputs: Validator Membership


//Public inputs for a validator membership proof.
//
//A validator uses this to prove they belong to the active validator set
//without revealing which validator they are.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct MembershipPublicInputs {
    //Root of the validator credential Merkle tree.
    //The verifier checks this matches the current on-chain validator root.
    pub validator_root: Hash256,

    //The epoch number. Credentials are valid for specific epochs.
    pub epoch: u64,

    //The slot number within the epoch.
    pub slot: u64,
}


//Public Inputs: ZK-ORIGIN State Lineage


//Public inputs for a ZK-ORIGIN state lineage proof.
//
//Each block's proof demonstrates that the state transition from
//prev_state_root to new_state_root is valid and links back to genesis.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct OriginPublicInputs {
    //The state root before this block's transitions.
    pub prev_state_root: Hash256,

    //The state root after this block's transitions.
    pub new_state_root: Hash256,

    //Block height this proof covers.
    pub block_height: u64,

    //Hash of the genesis block. Used to anchor the recursive chain.
    pub genesis_hash: Hash256,
}


//Verification Keys


//Verification key stored on-chain, used by pallet-proof-verifier to check
//incoming proofs. Keys are set during genesis or updated via governance.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum VerifyingKey {
    //Groth16 verifying key, serialized with ark-serialize.
    //Generated during trusted setup. Stored once, used for all transfer proofs.
    Groth16(Vec<u8>),

    //Halo2 verifying key. No trusted setup needed.
    //Generated from the circuit definition.
    Halo2(Vec<u8>),

    //Nova verifying key for ZK-ORIGIN.
    Nova(Vec<u8>),
}


//Proof Submission (the extrinsic payload)


//The top-level enum that pallet-proof-verifier receives.
//
//When a proof arrives on-chain (via an extrinsic call), it comes wrapped
//in one of these variants. The pallet dispatches to the correct verifier
//based on the variant.
//
//This is what the CLI sends and what the pallets receive.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum ProofSubmission {
    //A shielded transfer proof.
    //Verified by: arkworks Groth16 verifier
    //Then processed by: pallet-shielded-assets (update nullifiers + commitments)
    ShieldedTransfer {
        proof: Groth16Proof,
        inputs: TransferPublicInputs,
    },

    //A validator membership proof.
    //Verified by: Halo2 verifier
    //Then processed by: pallet-zk-validator (authorize block production)
    ValidatorMembership {
        proof: Halo2Proof,
        inputs: MembershipPublicInputs,
    },

    //A ZK-ORIGIN state lineage proof.
    //Verified by: Nova verifier
    //Then processed by: pallet-proof-verifier (update lineage chain)
    StateLineage {
        proof: NovaProof,
        inputs: OriginPublicInputs,
    },
}


//Proof Type identifier (for storage key lookups)


//Simple enum to identify which proof system a verifying key belongs to.
//Used as a storage key in pallet-proof-verifier's VerifyingKeys map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub enum ProofType {
    Groth16Transfer,
    Halo2Membership,
    NovaOrigin,
}


//Native ZERO token asset ID


//The predefined asset ID for the native ZERO token.
//All zeros. Other assets use Hash(issuance_params).
pub const NATIVE_ASSET_ID: AssetId = [0u8; 32];


//Tests


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
        //64 + 128 + 64 = 256 bytes of proof data
        //SCALE encoding adds no overhead for fixed-size arrays
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
        let submission = ProofSubmission::ShieldedTransfer {
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
        };
        let encoded = submission.encode();
        let decoded = ProofSubmission::decode(&mut &encoded[..]).unwrap();
        assert_eq!(submission, decoded);

        //Verify we can match on the variant
        match decoded {
            ProofSubmission::ShieldedTransfer { proof, inputs } => {
                assert_eq!(proof.a[0], 1);
                assert_eq!(inputs.nullifiers.len(), 1);
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
        };
        let encoded = inputs.encode();
        let decoded = OriginPublicInputs::decode(&mut &encoded[..]).unwrap();
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
        //ProofType is a simple enum with 3 variants, should be 1 byte
        assert_eq!(ProofType::max_encoded_len(), 1);
    }

    #[test]
    fn native_asset_id_is_all_zeros() {
        assert_eq!(NATIVE_ASSET_ID, [0u8; 32]);
    }
}
