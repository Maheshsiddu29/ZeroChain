//! ZK-ORIGIN: Recursive state lineage proofs using Nova
//! 
//! Proves that block N's state root is derived from block N-1's state root
//! through a valid state transition, and block N-1 traces back to genesis.

use nova_snark::{
    provider::PallasEngine,
    traits::{circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
    CompressedSNARK, PublicParams, RecursiveSNARK,
};
use ark_bn254::Fr;

pub mod step_circuit;

pub use step_circuit::*;

/// ZK-ORIGIN accumulator
/// 
/// Contains the folding proof that chains all blocks from genesis to current
pub struct ZkOriginAccumulator {
    pub recursive_snark: RecursiveSNARK<PallasEngine, StepCircuit, TrivialCircuit<<PallasEngine as Engine>::Scalar>>,
    pub current_height: u64,
}

impl ZkOriginAccumulator {
    /// Initialize at genesis
    pub fn genesis(genesis_hash: Fr) -> Self {
        let circuit_primary = StepCircuit::genesis(genesis_hash);
        let circuit_secondary = TrivialCircuit::default();
        
        // Create public parameters (one-time setup)
        let pp = PublicParams::setup(
            &circuit_primary,
            &circuit_secondary,
            &*S1::ck_floor(),
            &*S2::ck_floor(),
        );
        
        // Initialize recursive SNARK
        let recursive_snark = RecursiveSNARK::new(
            &pp,
            &circuit_primary,
            &circuit_secondary,
            &[genesis_hash],
            &[<PallasEngine as Engine>::Scalar::ZERO],
        ).unwrap();
        
        Self {
            recursive_snark,
            current_height: 0,
        }
    }
    
    /// Fold in a new block
    pub fn fold_block(
        &mut self,
        prev_state_root: Fr,
        new_state_root: Fr,
        block_height: u64,
    ) -> Result<(), String> {
        let step_circuit = StepCircuit {
            prev_state_root,
            new_state_root,
            block_height,
        };
        
        // Fold this step into the accumulator
        self.recursive_snark.prove_step(
            &pp,  // Need to store pp
            &step_circuit,
            &TrivialCircuit::default(),
        ).map_err(|e| format!("Fold failed: {:?}", e))?;
        
        self.current_height = block_height;
        Ok(())
    }
    
    /// Serialize accumulator to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        // Serialize RecursiveSNARK
        // This goes into NovaProof in primitives/zk-types
        todo!("Implement serialization")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fold_10_blocks() {
        let genesis_hash = Fr::from(0);
        let mut accumulator = ZkOriginAccumulator::genesis(genesis_hash);
        
        // Fold 10 blocks
        for height in 1..=10 {
            let prev_root = Fr::from(height - 1);
            let new_root = Fr::from(height);
            
            accumulator.fold_block(prev_root, new_root, height).unwrap();
        }
        
        assert_eq!(accumulator.current_height, 10);
        println!(" Folded 10 blocks successfully");
    }
}