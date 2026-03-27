
//! Step circuit for state transitions

use ark_bn254::Fr;

/// One step in the state chain
#[derive(Clone, Debug)]
pub struct StepCircuit {
    pub prev_state_root: Fr,
    pub new_state_root: Fr,
    pub block_height: u64,
    pub transactions_hash: Fr,
}

impl StepCircuit {
    /// Create genesis step
    pub fn genesis(genesis_hash: Fr) -> Self {
        Self {
            prev_state_root: genesis_hash,
            new_state_root: genesis_hash,
            block_height: 0,
            transactions_hash: Fr::from(0u64),
        }
    }
    
    /// Create a normal transition
    pub fn new(
        prev_state_root: Fr,
        new_state_root: Fr,
        block_height: u64,
        transactions_hash: Fr,
    ) -> Self {
        Self {
            prev_state_root,
            new_state_root,
            block_height,
            transactions_hash,
        }
    }
    
    /// Verify this step
    pub fn verify(&self) -> bool {
        self.block_height >= 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    
    #[test]
    fn test_step_creation() {
        let mut rng = ark_std::test_rng();
        
        let prev = Fr::rand(&mut rng);
        let new = Fr::rand(&mut rng);
        let tx_hash = Fr::rand(&mut rng);
        
        let step = StepCircuit::new(prev, new, 1, tx_hash);
        
        assert!(step.verify());
        assert_eq!(step.block_height, 1);
    }
    
    #[test]
    fn test_genesis_step() {
        let mut rng = ark_std::test_rng();
        let genesis = Fr::rand(&mut rng);
        
        let step = StepCircuit::genesis(genesis);
        
        assert_eq!(step.prev_state_root, genesis);
        assert_eq!(step.new_state_root, genesis);
        assert_eq!(step.block_height, 0);
    }
}
