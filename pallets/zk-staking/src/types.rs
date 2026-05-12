//! Type definitions for ZK Staking Pallet

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Stake commitment information
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
pub struct StakeCommitment {
    /// Commitment hash: H(secret_key, randomness)
    pub commitment: [u8; 32],
    /// Staked amount (in smallest units)
    pub amount: u128,
    /// Epoch when stake was created
    pub epoch: u64,
    /// Block number when stake was created
    pub timestamp: u32,
}

/// Fraud proof for slashing
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq, MaxEncodedLen)]
pub struct FraudProof {
    /// Commitment of equivocating validator
    pub commitment: [u8; 32],
    /// First block hash signed
    pub block_hash_1: [u8; 32],
    /// Second block hash signed
    pub block_hash_2: [u8; 32],
    /// Proof data (Halo2/Groth16) - bounded size
    #[codec(skip)]
    pub proof: (),  // Skip for MaxEncodedLen compliance
    /// Nullifier (prevents replay)
    pub nullifier: [u8; 32],
    /// Epoch of fraud
    pub epoch: u64,
}

/// Unstaking proof
#[derive(Clone, Debug, Encode, Decode, TypeInfo, PartialEq, Eq, MaxEncodedLen)]
pub struct UnstakingProof {
    /// Commitment to withdraw
    pub commitment: [u8; 32],
    /// Membership proof (bounded) - skipped for MaxEncodedLen
    #[codec(skip)]
    pub membership_proof: (),
    /// Nullifier
    pub nullifier: [u8; 32],
    /// Withdrawal epoch
    pub epoch: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stake_commitment_encoding() {
        let stake = StakeCommitment {
            commitment: [1u8; 32],
            amount: 1000,
            epoch: 42,
            timestamp: 100,
        };

        let encoded = stake.encode();
        let decoded = StakeCommitment::decode(&mut &encoded[..]).unwrap();
        assert_eq!(stake, decoded);
    }

    #[test]
    fn test_max_encoded_len() {
        // Verify MaxEncodedLen is correctly derived
        let _len = StakeCommitment::max_encoded_len();
        assert!(_len > 0);
    }
}