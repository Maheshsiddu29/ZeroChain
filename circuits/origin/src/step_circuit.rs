//! Step circuit for Nova IVC

use nova_snark::traits::circuit::StepCircuit as NovaStepCircuit;
use ark_bn254::Fr;
use ark_ff::PrimeField;

/// One step in the recursive chain: prove transition from prev_root to new_root
#[derive(Clone, Debug)]
pub struct StepCircuit {
    pub prev_state_root: Fr,
    pub new_state_root: Fr,
    pub block_height: u64,
}

impl StepCircuit {
    pub fn genesis(genesis_hash: Fr) -> Self {
        Self {
            prev_state_root: genesis_hash,
            new_state_root: genesis_hash,
            block_height: 0,
        }
    }
}

impl NovaStepCircuit<Fr> for StepCircuit {
    fn arity(&self) -> usize {
        // Number of public inputs
        3  // prev_root, new_root, height
    }
    
    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Fr>],
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        // Constraint: verify state transition is valid
        // For now, just pass through (real implementation checks block execution)
        
        let prev_root = AllocatedNum::alloc(cs.namespace(|| "prev_root"), || Ok(self.prev_state_root))?;
        let new_root = AllocatedNum::alloc(cs.namespace(|| "new_root"), || Ok(self.new_state_root))?;
        
        // Output new_root for next fold
        Ok(vec![new_root])
    }
}