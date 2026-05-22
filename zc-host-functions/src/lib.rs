//! Host Functions for ZK Proof Verification
//!
//! These functions run NATIVELY in the node (not in WASM runtime)
//! They handle expensive ZK verification that WASM cannot do efficiently.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod groth16_verifier;
pub mod halo2_verifier;
pub mod nova_verifier;
pub mod traits;

pub use groth16_verifier::Groth16Verifier;
pub use halo2_verifier::Halo2Verifier;
pub use nova_verifier::NovaVerifier;
pub use traits::ZkVerifierExt;

/// Unified ZK verification trait for host functions
///
/// This trait is implemented in the node and called from pallets via sp_io
pub trait UniversalVerifier {
    /// Verify Groth16 proof
    fn verify_groth16(
        proof: &[u8],
        vk: &[u8],
        public_inputs: &[[u8; 32]],
    ) -> bool;

    /// Verify Halo2 proof
    fn verify_halo2(
        proof: &[u8],
        vk: &[u8],
        public_inputs: &[[u8; 32]],
    ) -> bool;

    /// Verify Nova IVC proof
    fn verify_nova(
        accumulator: &[u8],
        vk: &[u8],
        genesis_root: [u8; 32],
        final_root: [u8; 32],
        num_steps: u64,
    ) -> bool;
}

/// Default verifier (can be overridden in node)
pub struct DefaultVerifier;

impl UniversalVerifier for DefaultVerifier {
    fn verify_groth16(proof: &[u8], vk: &[u8], public_inputs: &[[u8; 32]]) -> bool {
        Groth16Verifier::verify(proof, vk, public_inputs)
    }

    fn verify_halo2(proof: &[u8], vk: &[u8], public_inputs: &[[u8; 32]]) -> bool {
        Halo2Verifier::verify(proof, vk, public_inputs)
    }

    fn verify_nova(
        accumulator: &[u8],
        vk: &[u8],
        genesis_root: [u8; 32],
        final_root: [u8; 32],
        num_steps: u64,
    ) -> bool {
        NovaVerifier::verify(accumulator, vk, genesis_root, final_root, num_steps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_trait() {
        let _result = DefaultVerifier::verify_groth16(&[], &[], &[]);
        println!("✓ Verifier trait working");
    }
}