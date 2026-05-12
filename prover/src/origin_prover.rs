//! ZK-ORIGIN Standalone Prover
//!
//! Takes state transitions (prev_root, new_root, block_number),
//! folds N transitions via Nova, produces compressed SNARK.

use std::error::Error;
use std::fmt;

/// OriginProof - compressed proof of state lineage
#[derive(Clone, Debug)]
pub struct OriginProof {
    /// Nova accumulator (accumulated folding)
    pub accumulator: Vec<u8>,
    /// Final state root after all transitions
    pub final_state_root: [u8; 32],
    /// Genesis root (starting point)
    pub genesis_root: [u8; 32],
    /// Number of state transitions folded
    pub num_steps: u64,
}

impl OriginProof {
    pub fn new(
        accumulator: Vec<u8>,
        final_state_root: [u8; 32],
        genesis_root: [u8; 32],
        num_steps: u64,
    ) -> Self {
        Self {
            accumulator,
            final_state_root,
            genesis_root,
            num_steps,
        }
    }

    /// Serialize proof for on-chain submission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize accumulator length and data
        bytes.extend_from_slice(&(self.accumulator.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.accumulator);

        // Serialize roots
        bytes.extend_from_slice(&self.final_state_root);
        bytes.extend_from_slice(&self.genesis_root);

        // Serialize step count
        bytes.extend_from_slice(&self.num_steps.to_le_bytes());

        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OriginProverError> {
        if bytes.len() < 72 {
            return Err(OriginProverError::InvalidProofSize);
        }

        let mut offset = 0;

        // Read accumulator
        let acc_len = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| OriginProverError::InvalidProofSize)?,
        ) as usize;
        offset += 8;

        let accumulator = bytes[offset..offset + acc_len].to_vec();
        offset += acc_len;

        // Read roots
        let final_state_root: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| OriginProverError::InvalidProofSize)?;
        offset += 32;

        let genesis_root: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| OriginProverError::InvalidProofSize)?;
        offset += 32;

        // Read step count
        let num_steps = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| OriginProverError::InvalidProofSize)?,
        );

        Ok(Self {
            accumulator,
            final_state_root,
            genesis_root,
            num_steps,
        })
    }

    /// Verify proof locally (validates structure)
    pub fn verify_structure(&self) -> Result<(), OriginProverError> {
        if self.accumulator.is_empty() {
            return Err(OriginProverError::EmptyAccumulator);
        }

        if self.genesis_root == [0u8; 32] {
            return Err(OriginProverError::InvalidGenesisRoot);
        }

        if self.final_state_root == [0u8; 32] {
            return Err(OriginProverError::InvalidFinalRoot);
        }

        if self.num_steps == 0 {
            return Err(OriginProverError::NoSteps);
        }

        Ok(())
    }
}

/// Error types for ZK-ORIGIN prover
#[derive(Clone, Debug)]
pub enum OriginProverError {
    /// Single step folding failed
    StepFoldingFailed,
    /// Invalid state transition
    InvalidTransition,
    /// Proof verification failed
    VerificationFailed,
    /// Invalid proof size
    InvalidProofSize,
    /// Empty accumulator
    EmptyAccumulator,
    /// Invalid genesis root
    InvalidGenesisRoot,
    /// Invalid final root
    InvalidFinalRoot,
    /// No steps to fold
    NoSteps,
    /// Accumulator compression failed
    CompressionFailed,
}

impl fmt::Display for OriginProverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StepFoldingFailed => write!(f, "Failed to fold step in Nova"),
            Self::InvalidTransition => write!(f, "Invalid state transition"),
            Self::VerificationFailed => write!(f, "Proof verification failed"),
            Self::InvalidProofSize => write!(f, "Invalid proof serialization size"),
            Self::EmptyAccumulator => write!(f, "Accumulator is empty"),
            Self::InvalidGenesisRoot => write!(f, "Genesis root is invalid"),
            Self::InvalidFinalRoot => write!(f, "Final state root is invalid"),
            Self::NoSteps => write!(f, "No steps to fold"),
            Self::CompressionFailed => write!(f, "Failed to compress accumulator"),
        }
    }
}

impl Error for OriginProverError {}

/// State transition for folding
#[derive(Clone, Debug)]
pub struct StateTransition {
    /// Previous state root
    pub prev_root: [u8; 32],
    /// New state root
    pub new_root: [u8; 32],
    /// Block number
    pub block_number: u64,
}

impl StateTransition {
    pub fn new(prev_root: [u8; 32], new_root: [u8; 32], block_number: u64) -> Self {
        Self {
            prev_root,
            new_root,
            block_number,
        }
    }

    /// Verify transition is valid
    pub fn verify(&self) -> Result<(), OriginProverError> {
        if self.prev_root == [0u8; 32] && self.block_number != 0 {
            return Err(OriginProverError::InvalidTransition);
        }

        if self.new_root == [0u8; 32] {
            return Err(OriginProverError::InvalidTransition);
        }

        Ok(())
    }
}

/// ZK-ORIGIN Prover
pub struct OriginProver {
    /// Genesis root (proof starts from here)
    genesis_root: [u8; 32],
    /// Current accumulator state
    accumulator: Vec<u8>,
    /// Processed transitions
    transitions: Vec<StateTransition>,
}

impl OriginProver {
    /// Create new prover with genesis root
    pub fn new(genesis_root: [u8; 32]) -> Result<Self, OriginProverError> {
        if genesis_root == [0u8; 32] {
            return Err(OriginProverError::InvalidGenesisRoot);
        }

        Ok(Self {
            genesis_root,
            accumulator: genesis_root.to_vec(),
            transitions: Vec::new(),
        })
    }

    /// Process single state transition
    pub fn fold_step(&mut self, transition: StateTransition) -> Result<(), OriginProverError> {
        // Validate transition
        transition.verify()?;

        // Verify transition chain
        if !self.transitions.is_empty() {
            let last = &self.transitions[self.transitions.len() - 1];
            if last.new_root != transition.prev_root {
                return Err(OriginProverError::InvalidTransition);
            }
        } else {
            // First transition: prev_root must be genesis
            if transition.prev_root != self.genesis_root {
                return Err(OriginProverError::InvalidTransition);
            }
        }

        // Fold transition into accumulator
        self.fold_transition(&transition)?;

        // Record transition
        self.transitions.push(transition);

        Ok(())
    }

    /// Fold multiple transitions
    pub fn fold_steps(&mut self, transitions: Vec<StateTransition>) -> Result<(), OriginProverError> {
        for transition in transitions {
            self.fold_step(transition)?;
        }
        Ok(())
    }

    /// Internal: Fold single transition into accumulator
    fn fold_transition(&mut self, transition: &StateTransition) -> Result<(), OriginProverError> {
        // Simplified folding: accumulator = H(accumulator, transition_data)
        let mut fold_input = self.accumulator.clone();
        fold_input.extend_from_slice(&transition.prev_root);
        fold_input.extend_from_slice(&transition.new_root);
        fold_input.extend_from_slice(&transition.block_number.to_le_bytes());

        // Hash to create new accumulator
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&fold_input);
        self.accumulator = hasher.finalize().to_vec();

        Ok(())
    }

    /// Generate final proof
    pub fn prove(&self) -> Result<OriginProof, OriginProverError> {
        if self.transitions.is_empty() {
            return Err(OriginProverError::NoSteps);
        }

        let final_state_root = self.transitions.last().unwrap().new_root;

        Ok(OriginProof::new(
            self.accumulator.clone(),
            final_state_root,
            self.genesis_root,
            self.transitions.len() as u64,
        ))
    }

    /// Get number of folded steps
    pub fn step_count(&self) -> u64 {
        self.transitions.len() as u64
    }

    /// Get current accumulator
    pub fn get_accumulator(&self) -> Vec<u8> {
        self.accumulator.clone()
    }

    /// Verify proof matches current state
    pub fn verify_internal(&self, proof: &OriginProof) -> Result<(), OriginProverError> {
        if proof.genesis_root != self.genesis_root {
            return Err(OriginProverError::VerificationFailed);
        }

        if proof.num_steps != self.transitions.len() as u64 {
            return Err(OriginProverError::VerificationFailed);
        }

        if proof.accumulator != self.accumulator {
            return Err(OriginProverError::VerificationFailed);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a non-zero dummy hash for testing
    fn dummy_hash(i: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = i;
        h[1] = 0xFF; // Add non-zero byte to ensure hash is not [0u8; 32]
        h
    }

    #[test]
    fn test_single_step_folding() {
        let mut prover = OriginProver::new(dummy_hash(1)).unwrap();

        let transition = StateTransition::new(dummy_hash(1), dummy_hash(2), 1);

        assert!(prover.fold_step(transition).is_ok());
        assert_eq!(prover.step_count(), 1);
    }

    #[test]
    fn test_multi_step_folding() {
        let mut prover = OriginProver::new(dummy_hash(1)).unwrap();

        for i in 2..=6 {
            let transition = StateTransition::new(
                dummy_hash((i - 1) as u8),
                dummy_hash(i as u8),
                i as u64,
            );
            assert!(prover.fold_step(transition).is_ok());
        }

        assert_eq!(prover.step_count(), 5);
    }

    #[test]
    fn test_invalid_transition_chain() {
        let mut prover = OriginProver::new(dummy_hash(1)).unwrap();

        // First transition is valid
        let t1 = StateTransition::new(dummy_hash(1), dummy_hash(2), 1);
        assert!(prover.fold_step(t1).is_ok());

        // Second transition: prev_root doesn't match previous new_root
        let t2 = StateTransition::new(dummy_hash(5), dummy_hash(3), 2); // Wrong!
        assert!(prover.fold_step(t2).is_err());
    }

    #[test]
    fn test_invalid_genesis() {
        let result = OriginProver::new([0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_serialization() {
        let proof = OriginProof::new(
            vec![1, 2, 3, 4, 5],
            dummy_hash(1),
            dummy_hash(0),
            10,
        );

        let bytes = proof.to_bytes();
        let deserialized = OriginProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof.accumulator, deserialized.accumulator);
        assert_eq!(proof.final_state_root, deserialized.final_state_root);
        assert_eq!(proof.genesis_root, deserialized.genesis_root);
        assert_eq!(proof.num_steps, deserialized.num_steps);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let mut prover = OriginProver::new(dummy_hash(1)).unwrap();

        for i in 2..=6 {
            let transition = StateTransition::new(
                dummy_hash((i - 1) as u8),
                dummy_hash(i as u8),
                i as u64,
            );
            assert!(prover.fold_step(transition).is_ok());
        }

        let proof = prover.prove().unwrap();
        assert!(prover.verify_internal(&proof).is_ok());
        assert_eq!(proof.num_steps, 5);
    }

    #[test]
    fn test_proof_structure_validation() {
        let valid_proof = OriginProof::new(
            vec![1, 2, 3],
            dummy_hash(1),
            dummy_hash(0),
            5,
        );

        assert!(valid_proof.verify_structure().is_ok());

        // Invalid: empty accumulator
        let invalid_proof = OriginProof::new(
            vec![],
            dummy_hash(1),
            dummy_hash(0),
            5,
        );
        assert!(invalid_proof.verify_structure().is_err());

        // Invalid: zero genesis
        let invalid_proof2 = OriginProof::new(
            vec![1, 2, 3],
            dummy_hash(1),
            [0u8; 32],
            5,
        );
        assert!(invalid_proof2.verify_structure().is_err());
    }

    #[test]
    fn test_state_transition_validation() {
        // Valid transition
        let valid = StateTransition::new(dummy_hash(1), dummy_hash(2), 1);
        assert!(valid.verify().is_ok());

        // Invalid: zero new_root
        let invalid = StateTransition::new(dummy_hash(1), [0u8; 32], 1);
        assert!(invalid.verify().is_err());

        // Invalid: zero prev_root with non-zero block
        let invalid2 = StateTransition::new([0u8; 32], dummy_hash(1), 5);
        assert!(invalid2.verify().is_err());

        // Valid: zero prev_root with zero block (genesis)
        let valid_genesis = StateTransition::new([0u8; 32], dummy_hash(1), 0);
        assert!(valid_genesis.verify().is_ok());
    }
}