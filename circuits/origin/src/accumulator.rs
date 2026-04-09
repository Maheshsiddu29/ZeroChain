//! Accumulator for incremental state verification

use ark_bn254::Fr;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use crate::step_circuit::StateTransitionCircuit;

pub struct OriginAccumulator {
    pub current_height: u64,
    pub state_root: Fr,
    pub steps: Vec<StateTransitionCircuit>,
}

impl OriginAccumulator {
    pub fn genesis(initial_state: Fr) -> Self {
        Self {
            current_height: 0,
            state_root: initial_state,
            steps: Vec::new(),
        }
    }

    pub fn fold_block(
        &mut self,
        prev_state: Fr,
        new_state: Fr,
        height: u64,
    ) -> Result<(), String> {
        if self.current_height > 0 && height != self.current_height + 1 {
            return Err("Height mismatch".to_string());
        }

        if prev_state != self.state_root {
            return Err("State root mismatch".to_string());
        }

        let step = StateTransitionCircuit::new(prev_state, new_state, height);
        self.steps.push(step);
        self.state_root = new_state;
        self.current_height = height;

        Ok(())
    }

    pub fn verify(&self) -> Result<(), String> {
        for step in &self.steps {
            if step.block_height > self.current_height {
                return Err("Invalid step height".to_string());
            }
        }
        Ok(())
    }

    pub fn compress(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.current_height.to_le_bytes());
        
        self.state_root.serialize_compressed(&mut bytes)
            .map_err(|e| format!("Serialization error: {:?}", e))?;
        
        Ok(bytes)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        self.compress()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 8 {
            return Err("Invalid bytes: too short".to_string());
        }

        let height = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let state_root = Fr::deserialize_compressed(&bytes[8..])
            .map_err(|e| format!("Deserialization error: {:?}", e))?;

        Ok(Self {
            current_height: height,
            state_root,
            steps: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accumulator_genesis() {
        let genesis_state = Fr::from(0u64);
        let acc = OriginAccumulator::genesis(genesis_state);
        
        assert_eq!(acc.current_height, 0);
        assert_eq!(acc.state_root, genesis_state);
        assert_eq!(acc.steps.len(), 0);
    }

    #[test]
    fn test_accumulator_fold() {
        let genesis_state = Fr::from(0u64);
        let mut acc = OriginAccumulator::genesis(genesis_state);
        
        let new_state = Fr::from(1u64);
        let result = acc.fold_block(genesis_state, new_state, 1);
        
        assert!(result.is_ok());
        assert_eq!(acc.current_height, 1);
        assert_eq!(acc.state_root, new_state);
    }

    #[test]
    fn test_accumulator_serialization() {
        let genesis_state = Fr::from(42u64);
        let acc = OriginAccumulator::genesis(genesis_state);
        
        let bytes = acc.to_bytes().unwrap();
        let acc2 = OriginAccumulator::from_bytes(&bytes).unwrap();
        
        assert_eq!(acc.current_height, acc2.current_height);
        assert_eq!(acc.state_root, acc2.state_root);
    }
}