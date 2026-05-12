//! ZeroChain Prover Library
//! 
//! Public API for zero-knowledge proof generation and verification

pub mod origin_prover;
pub mod groth16_prover;
pub mod serialization;

// Re-export main ZK-ORIGIN types
pub use origin_prover::{
    OriginProof, 
    StateTransition, 
    OriginProver,
    OriginProverError,
};

// Re-export Groth16 utilities
pub use groth16_prover::{
    generate_transfer_proof,
    verify_transfer_proof,
    TransferPublicInputs,
};

// Re-export serialization utilities
pub use serialization::{
    serialize_proof,
    deserialize_proof,
    ProofMetadata,
};