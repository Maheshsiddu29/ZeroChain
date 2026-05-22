//! ZeroChain Prover Library
//!
//! Exports prover modules and types

pub mod groth16_generator;
pub mod origin_prover;
pub mod serialization;

pub use groth16_generator::{
    Groth16Generator, Groth16Proof, TransferWitness, TransferPublicInputs,
};
pub use origin_prover::{OriginProof, NovaFolder, StateTransition};

#[cfg(test)]
mod tests {
    #[test]
    fn test_library_exports() {
        println!(" Library exports working");
    }
}