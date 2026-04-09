//! State transition step circuit for ZK-ORIGIN
//!
//! Stubbed until Nova version compatible with ark 0.4.x is available.

use ark_bn254::Fr;


/// Placeholder for the state transition circuit
pub struct StateTransitionCircuit {
    pub prev_state_root: Fr,
    pub new_state_root: Fr,
    pub block_height: u64,
}

impl StateTransitionCircuit {
    /// Create a new step circuit
    pub fn new(prev_state_root: Fr, new_state_root: Fr, block_height: u64) -> Self {
        Self {
            prev_state_root,
            new_state_root,
            block_height,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step_circuit_creation() {
        let circuit = StateTransitionCircuit::new(
            Fr::from(0u64),
            Fr::from(1u64),
            1,
        );
        assert_eq!(circuit.block_height, 1);
    }
}