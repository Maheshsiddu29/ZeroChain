//! ZK-ORIGIN folding tests
//! Stubbed until Nova integration is complete.

use origin_circuit::step_circuit::StateTransitionCircuit;
use ark_bn254::Fr;

#[test]
fn test_basic_step_circuit() {
    let circuit = StateTransitionCircuit::new(
        Fr::from(0u64),
        Fr::from(1u64),
        1,
    );
    assert_eq!(circuit.block_height, 1);
}