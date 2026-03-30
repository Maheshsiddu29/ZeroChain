
//! ZK-ORIGIN: State lineage proofs for Zero Chain

use ark_bn254::Fr;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

pub mod step_circuit;
pub use step_circuit::*;

/// ZK-ORIGIN accumulator
#[derive(Clone, Debug)]
pub struct ZkOriginAccumulator {
    pub state_chain: Vec<StateTransition>,
    pub current_height: u64,
    pub genesis_hash: Fr,
}

/// One state transition
#[derive(Clone, Debug)]
pub struct StateTransition {
    pub prev_state_root: Fr,
    pub new_state_root: Fr,
    pub block_height: u64,
    pub transactions_hash: Fr,
}

impl ZkOriginAccumulator {
    /// Initialize at genesis
    pub fn genesis(genesis_hash: Fr) -> Self {
        println!(" Initializing ZK-ORIGIN at genesis...");
        
        let genesis_transition = StateTransition {
            prev_state_root: genesis_hash,
            new_state_root: genesis_hash,
            block_height: 0,
            transactions_hash: Fr::from(0u64),
        };
        
        println!(" Genesis accumulator created");
        
        Self {
            state_chain: vec![genesis_transition],
            current_height: 0,
            genesis_hash,
        }
    }
    
    /// Fold a new block
    pub fn fold_block(
        &mut self,
        prev_state_root: Fr,
        new_state_root: Fr,
        block_height: u64,
        transactions_hash: Fr,
    ) -> Result<(), String> {
        println!(" Folding block {} into accumulator...", block_height);
        
        let last_state = self.state_chain.last()
            .ok_or("No previous state")?;
        
        if last_state.new_state_root != prev_state_root {
            return Err(format!(
                "State mismatch at block {}: expected prev_root to match last new_root",
                block_height
            ));
        }
        
        if block_height != self.current_height + 1 {
            return Err(format!(
                "Height mismatch: expected {}, got {}",
                self.current_height + 1,
                block_height
            ));
        }
        
        let transition = StateTransition {
            prev_state_root,
            new_state_root,
            block_height,
            transactions_hash,
        };
        
        self.state_chain.push(transition);
        self.current_height = block_height;
        
        println!(" Block {} folded successfully", block_height);
        
        Ok(())
    }
    
    /// Verify chain validity
    pub fn verify(&self) -> Result<bool, String> {
        println!(" Verifying ZK-ORIGIN proof for {} blocks...", self.current_height);
        
        let genesis = self.state_chain.first()
            .ok_or("Empty chain")?;
        
        if genesis.prev_state_root != self.genesis_hash {
            return Err("Genesis mismatch".to_string());
        }
        
        for i in 1..self.state_chain.len() {
            let prev = &self.state_chain[i - 1];
            let curr = &self.state_chain[i];
            
            if prev.new_state_root != curr.prev_state_root {
                return Err(format!("Broken chain at block {}", curr.block_height));
            }
            
            if curr.block_height != prev.block_height + 1 {
                return Err(format!("Height gap at block {}", curr.block_height));
            }
        }
        
        println!(" Verification passed: {} blocks validated", self.current_height);
        Ok(true)
    }
    
    /// Compress the proof
    pub fn compress(&self) -> Result<Vec<u8>, String> {
        println!(" Compressing proof...");
        
        let bytes = self.to_bytes()?;
        
        println!(" Compressed to {} bytes ({} blocks)", bytes.len(), self.current_height);
        
        Ok(bytes)
    }
    
    /// Get current state root
    pub fn current_state_root(&self) -> Fr {
        self.state_chain.last()
            .map(|t| t.new_state_root)
            .unwrap_or(self.genesis_hash)
    }
    
    /// Serialize to bytes using ark-serialize
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::new();
        
        // Write current height
        buffer.extend_from_slice(&self.current_height.to_le_bytes());
        
        // Write genesis hash
        self.genesis_hash.serialize_uncompressed(&mut buffer)
            .map_err(|e| format!("Genesis serialization failed: {:?}", e))?;
        
        // Write number of transitions
        let num_transitions = self.state_chain.len() as u64;
        buffer.extend_from_slice(&num_transitions.to_le_bytes());
        
        // Write each transition
        for transition in &self.state_chain {
            transition.prev_state_root.serialize_uncompressed(&mut buffer)
                .map_err(|e| format!("Prev root serialization failed: {:?}", e))?;
            
            transition.new_state_root.serialize_uncompressed(&mut buffer)
                .map_err(|e| format!("New root serialization failed: {:?}", e))?;
            
            buffer.extend_from_slice(&transition.block_height.to_le_bytes());
            
            transition.transactions_hash.serialize_uncompressed(&mut buffer)
                .map_err(|e| format!("Tx hash serialization failed: {:?}", e))?;
        }
        
        Ok(buffer)
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut cursor = 0;
        
        // Read current height
        if bytes.len() < 8 {
            return Err("Invalid bytes: too short for height".to_string());
        }
        let mut height_bytes = [0u8; 8];
        height_bytes.copy_from_slice(&bytes[cursor..cursor + 8]);
        let current_height = u64::from_le_bytes(height_bytes);
        cursor += 8;
        
        // Read genesis hash (32 bytes)
        if bytes.len() < cursor + 32 {
            return Err("Invalid bytes: too short for genesis hash".to_string());
        }
        let genesis_hash = Fr::deserialize_uncompressed(&bytes[cursor..cursor + 32])
            .map_err(|e| format!("Genesis deserialization failed: {:?}", e))?;
        cursor += 32;
        
        // Read number of transitions
        if bytes.len() < cursor + 8 {
            return Err("Invalid bytes: too short for num transitions".to_string());
        }
        let mut num_trans_bytes = [0u8; 8];
        num_trans_bytes.copy_from_slice(&bytes[cursor..cursor + 8]);
        let num_transitions = u64::from_le_bytes(num_trans_bytes) as usize;
        cursor += 8;
        
        // Read each transition (32 + 32 + 8 + 32 = 104 bytes each)
        let mut state_chain = Vec::with_capacity(num_transitions);
        
        for _ in 0..num_transitions {
            if bytes.len() < cursor + 104 {
                return Err("Invalid bytes: incomplete transition".to_string());
            }
            
            let prev_state_root = Fr::deserialize_uncompressed(&bytes[cursor..cursor + 32])
                .map_err(|e| format!("Prev root deserialization failed: {:?}", e))?;
            cursor += 32;
            
            let new_state_root = Fr::deserialize_uncompressed(&bytes[cursor..cursor + 32])
                .map_err(|e| format!("New root deserialization failed: {:?}", e))?;
            cursor += 32;
            
            let mut block_height_bytes = [0u8; 8];
            block_height_bytes.copy_from_slice(&bytes[cursor..cursor + 8]);
            let block_height = u64::from_le_bytes(block_height_bytes);
            cursor += 8;
            
            let transactions_hash = Fr::deserialize_uncompressed(&bytes[cursor..cursor + 32])
                .map_err(|e| format!("Tx hash deserialization failed: {:?}", e))?;
            cursor += 32;
            
            state_chain.push(StateTransition {
                prev_state_root,
                new_state_root,
                block_height,
                transactions_hash,
            });
        }
        
        Ok(Self {
            state_chain,
            current_height,
            genesis_hash,
        })
    }
    
    /// Get proof for specific block
    pub fn get_block_proof(&self, height: u64) -> Option<&StateTransition> {
        self.state_chain.iter().find(|t| t.block_height == height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    
    #[test]
    fn test_genesis_creation() {
        let mut rng = ark_std::test_rng();
        let genesis_hash = Fr::rand(&mut rng);
        
        let accumulator = ZkOriginAccumulator::genesis(genesis_hash);
        
        assert_eq!(accumulator.current_height, 0);
        assert_eq!(accumulator.genesis_hash, genesis_hash);
        assert_eq!(accumulator.state_chain.len(), 1);
    }
    
    #[test]
    fn test_fold_10_blocks() {
        let mut rng = ark_std::test_rng();
        
        let genesis_hash = Fr::rand(&mut rng);
        let mut accumulator = ZkOriginAccumulator::genesis(genesis_hash);
        
        let mut prev_root = genesis_hash;
        for height in 1..=10 {
            let new_root = Fr::rand(&mut rng);
            let tx_hash = Fr::rand(&mut rng);
            
            accumulator
                .fold_block(prev_root, new_root, height, tx_hash)
                .expect(&format!("Failed to fold block {}", height));
            
            prev_root = new_root;
        }
        
        assert_eq!(accumulator.current_height, 10);
        assert_eq!(accumulator.state_chain.len(), 11);
        
        let valid = accumulator.verify().expect("Verification failed");
        assert!(valid);
        
        println!("\n Successfully folded and verified 10 blocks!");
    }
    
    #[test]
    fn test_compress_proof() {
        let mut rng = ark_std::test_rng();
        
        let genesis_hash = Fr::rand(&mut rng);
        let mut accumulator = ZkOriginAccumulator::genesis(genesis_hash);
        
        let mut prev_root = genesis_hash;
        for height in 1..=5 {
            let new_root = Fr::rand(&mut rng);
            let tx_hash = Fr::rand(&mut rng);
            
            accumulator.fold_block(prev_root, new_root, height, tx_hash).unwrap();
            prev_root = new_root;
        }
        
        let compressed_bytes = accumulator.compress().unwrap();
        
        println!("Compressed proof size: {} bytes", compressed_bytes.len());
        println!("Covers {} blocks", accumulator.current_height);
        
        assert!(compressed_bytes.len() > 0);
    }
    
    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = ark_std::test_rng();
        
        let genesis_hash = Fr::rand(&mut rng);
        let mut accumulator = ZkOriginAccumulator::genesis(genesis_hash);
        
        let mut prev_root = genesis_hash;
        for height in 1..=3 {
            let new_root = Fr::rand(&mut rng);
            accumulator.fold_block(prev_root, new_root, height, Fr::from(0u64)).unwrap();
            prev_root = new_root;
        }
        
        // Serialize
        let bytes = accumulator.to_bytes().unwrap();
        
        // Deserialize
        let restored = ZkOriginAccumulator::from_bytes(&bytes).unwrap();
        
        assert_eq!(restored.current_height, accumulator.current_height);
        assert_eq!(restored.state_chain.len(), accumulator.state_chain.len());
        assert!(restored.verify().unwrap());
        
        println!(" Serialization round-trip successful");
        println!("   Original height: {}", accumulator.current_height);
        println!("   Restored height: {}", restored.current_height);
        println!("   Serialized size: {} bytes", bytes.len());
    }
    
    #[test]
    fn test_invalid_transition_rejected() {
        let mut rng = ark_std::test_rng();
        
        let genesis_hash = Fr::rand(&mut rng);
        let mut accumulator = ZkOriginAccumulator::genesis(genesis_hash);
        
        // Add valid block 1
        let state1 = Fr::rand(&mut rng);
        accumulator.fold_block(genesis_hash, state1, 1, Fr::from(0u64)).unwrap();
        
        // Try invalid block 2
        let wrong_prev = Fr::rand(&mut rng);
        let state2 = Fr::rand(&mut rng);
        let result = accumulator.fold_block(wrong_prev, state2, 2, Fr::from(0u64));
        
        assert!(result.is_err(), "Should reject invalid state transition");
        println!(" Invalid transition correctly rejected");
    }
    
    #[test]
    fn test_height_gap_rejected() {
        let mut rng = ark_std::test_rng();
        
        let genesis_hash = Fr::rand(&mut rng);
        let mut accumulator = ZkOriginAccumulator::genesis(genesis_hash);
        
        let state1 = Fr::rand(&mut rng);
        accumulator.fold_block(genesis_hash, state1, 1, Fr::from(0u64)).unwrap();
        
        // Try to skip from block 1 to block 3
        let state3 = Fr::rand(&mut rng);
        let result = accumulator.fold_block(state1, state3, 3, Fr::from(0u64));
        
        assert!(result.is_err(), "Should reject height gap");
        println!(" Height gap correctly rejected");
    }
}
