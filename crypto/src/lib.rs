#![cfg_attr(not(feature = "std"), no_std)]

//! ZeroChain Cryptographic Primitives
//!
//! This crate provides:
//! - Poseidon hashing
//! - Merkle tree operations
//! - Nullifier generation
//! - Commitments

pub mod poseidon;
pub mod merkle;
pub mod nullifier;
pub mod commitment;

pub use poseidon::*;
pub use merkle::*;
pub use nullifier::*;
pub use commitment::*;

// Re-export the field type used throughout ZeroChain
pub use ark_bn254::Fr as Field;