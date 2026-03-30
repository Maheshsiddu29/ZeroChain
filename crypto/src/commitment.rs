//! Pedersen-style commitments using Poseidon hash
//!
//! commitment = Poseidon(value, blinding_factor)

#![cfg_attr(not(feature = "std"), no_std)]

use ark_bn254::Fr;
use crate::poseidon::PoseidonHasher;

/// A hiding commitment: H(value || blinding)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub value: Fr,
}

impl Commitment {
    /// Create a new commitment: Poseidon(value, blinding)
    pub fn commit(value: Fr, blinding: Fr) -> Self {
        let hasher = PoseidonHasher::new();
        let hash = hasher.hash_two(value, blinding);
        Self { value: hash }
    }

    /// Get the commitment as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        use ark_serialize::CanonicalSerialize;
        let mut buf = [0u8; 32];
        self.value.serialize_compressed(&mut buf[..]).expect("serialization failed");
        buf
    }
}
