//! ZK-ORIGIN Circuit (Nova IVC)
//!
//! Placeholder until Nova 0.5.x compatibility
//!
//! **EXPERIMENTAL — not security-audited, disabled in production builds.**

pub mod step_circuit;
pub mod accumulator;

pub use step_circuit::StateTransitionCircuit;
pub use accumulator::OriginAccumulator;