//! Groth16 SNARK Proof Generation
//!
//! Generates Groth16 proofs for shielded transfers
//! Uses arkworks for BLS12-381 curve operations

use std::fmt;
use zc_crypto::poseidon::PoseidonHasher;

// ── Real circuit proving (TransferCircuit + Groth16/BN254) ──────────────────

/// Proving key bundle for the fixed-shape TransferCircuit.
pub struct TransferCircuitKeys {
    pub proving_key: ark_groth16::ProvingKey<ark_bn254::Bn254>,
    pub verifying_key: ark_groth16::VerifyingKey<ark_bn254::Bn254>,
}

/// Generate proving and verifying keys for the fixed-shape TransferCircuit.
///
/// This runs Groth16 setup using `TransferCircuit::default()` (all dummy slots).
/// The fixed circuit shape ensures the keys are valid for any actual transfer.
///
/// WARNING: This function is expensive (seconds) — run once and persist the keys.
pub fn setup_transfer_circuit_keys(
    rng: &mut (impl ark_std::rand::Rng + ark_std::rand::CryptoRng),
) -> Result<TransferCircuitKeys, Groth16Error> {
    use ark_groth16::Groth16;
    use ark_snark::CircuitSpecificSetupSNARK;
    use ark_bn254::Bn254;
    use transfer_circuit::TransferCircuit;

    let (proving_key, verifying_key) = Groth16::<Bn254>::setup(TransferCircuit::default(), rng)
        .map_err(|e| Groth16Error::ProofGenerationFailed(format!("Groth16 setup failed: {e}")))?;

    Ok(TransferCircuitKeys { proving_key, verifying_key })
}

/// Generate a real Groth16 proof for a TransferCircuit.
///
/// The proving key must have been generated for the SAME circuit shape
/// (i.e., from `setup_transfer_circuit_keys`).
pub fn prove_transfer_circuit(
    circuit: transfer_circuit::TransferCircuit,
    keys: &TransferCircuitKeys,
    rng: &mut (impl ark_std::rand::Rng + ark_std::rand::CryptoRng),
) -> Result<ark_groth16::Proof<ark_bn254::Bn254>, Groth16Error> {
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_bn254::Bn254;

    Groth16::<Bn254>::prove(&keys.proving_key, circuit, rng)
        .map_err(|e| Groth16Error::ProofGenerationFailed(format!("Groth16 prove failed: {e}")))
}

/// Verify a TransferCircuit proof against a list of public inputs.
///
/// Public inputs must be ordered as produced by `TransferCircuit::generate_constraints`:
///   [merkle_root, nullifiers×MAX_INPUTS, output_commitments×MAX_OUTPUTS, asset_id, fee_commitment]
pub fn verify_transfer_circuit_proof(
    proof: &ark_groth16::Proof<ark_bn254::Bn254>,
    keys: &TransferCircuitKeys,
    public_inputs: &[ark_bn254::Fr],
) -> bool {
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_bn254::Bn254;

    Groth16::<Bn254>::verify(&keys.verifying_key, public_inputs, proof).unwrap_or(false)
}

/// Groth16 Generation Error
#[derive(Clone, Debug)]
pub enum Groth16Error {
    SerializationError(String),
    ProofGenerationFailed(String),
    InvalidWitness(String),
    InvalidCircuit(String),
}

impl fmt::Display for Groth16Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::ProofGenerationFailed(msg) => write!(f, "Proof generation failed: {}", msg),
            Self::InvalidWitness(msg) => write!(f, "Invalid witness: {}", msg),
            Self::InvalidCircuit(msg) => write!(f, "Invalid circuit: {}", msg),
        }
    }
}

impl std::error::Error for Groth16Error {}

/// Transfer witness (private inputs)
#[derive(Clone, Debug)]
pub struct TransferWitness {
    /// Sender's secret
    pub secret: [u8; 32],
    /// Random nonce for commitment
    pub randomness: [u8; 32],
    /// Amount to transfer
    pub amount: u128,
    /// Merkle path (for membership proof)
    pub merkle_path: Vec<[u8; 32]>,
    /// Path indices
    pub merkle_indices: Vec<bool>,
}

impl TransferWitness {
    /// Validate witness structure
    pub fn validate(&self) -> Result<(), Groth16Error> {
        if self.secret == [0u8; 32] {
            return Err(Groth16Error::InvalidWitness(
                "Secret cannot be zero".to_string(),
            ));
        }

        if self.amount == 0 {
            return Err(Groth16Error::InvalidWitness(
                "Amount must be positive".to_string(),
            ));
        }

        if self.merkle_path.is_empty() {
            return Err(Groth16Error::InvalidWitness(
                "Empty merkle path".to_string(),
            ));
        }

        Ok(())
    }

    /// Compute commitment: Poseidon(secret, randomness)
    pub fn compute_commitment(&self) -> [u8; 32] {
        PoseidonHasher::hash_two(&self.secret, &self.randomness)
    }

    /// Compute nullifier: Poseidon(secret, amount_bytes)
    pub fn compute_nullifier(&self) -> [u8; 32] {
        let mut amount_bytes = [0u8; 32];
        amount_bytes[..16].copy_from_slice(&self.amount.to_le_bytes());
        PoseidonHasher::hash_two(&self.secret, &amount_bytes)
    }

    /// Compute merkle root from path
    pub fn compute_root(&self) -> Result<[u8; 32], Groth16Error> {
        if self.merkle_path.len() != self.merkle_indices.len() {
            return Err(Groth16Error::InvalidWitness(
                "Path length mismatch".to_string(),
            ));
        }

        let mut current = self.compute_commitment();

        for (sibling, is_right) in self.merkle_path.iter().zip(self.merkle_indices.iter()) {
            current = if *is_right {
                PoseidonHasher::hash_two(&current, sibling)
            } else {
                PoseidonHasher::hash_two(sibling, &current)
            };
        }

        Ok(current)
    }
}

/// Public inputs for transfer proof
#[derive(Clone, Debug)]
pub struct TransferPublicInputs {
    /// Commitment of sender
    pub commitment: [u8; 32],
    /// Nullifier (prevents double-spend)
    pub nullifier: [u8; 32],
    /// Merkle root (proves commitment is valid)
    pub root: [u8; 32],
    /// Recipient commitment
    pub recipient_commitment: [u8; 32],
    /// Amount
    pub amount: u128,
}

impl TransferPublicInputs {
    /// Create from witness
    pub fn from_witness(
        witness: &TransferWitness,
        recipient: [u8; 32],
    ) -> Result<Self, Groth16Error> {
        let commitment = witness.compute_commitment();
        let nullifier = witness.compute_nullifier();
        let root = witness.compute_root()?;

        Ok(Self {
            commitment,
            nullifier,
            root,
            recipient_commitment: recipient,
            amount: witness.amount,
        })
    }

    /// Convert to field elements for circuit
    pub fn to_field_elements(&self) -> Result<Vec<[u8; 32]>, Groth16Error> {
        let mut elements = Vec::new();

        // Convert each [u8; 32] to field element
        elements.push(self.commitment);
        elements.push(self.nullifier);
        elements.push(self.root);
        elements.push(self.recipient_commitment);

        Ok(elements)
    }
}

/// Groth16 Proof
#[derive(Clone, Debug)]
pub struct Groth16Proof {
    /// Proof bytes (96 bytes for BLS12-381)
    pub proof: Vec<u8>,
    /// Public inputs
    pub public_inputs: TransferPublicInputs,
}

impl Groth16Proof {
    /// Serialize proof for on-chain submission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize proof
        bytes.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.proof);

        // Serialize public inputs
        bytes.extend_from_slice(&self.public_inputs.commitment);
        bytes.extend_from_slice(&self.public_inputs.nullifier);
        bytes.extend_from_slice(&self.public_inputs.root);
        bytes.extend_from_slice(&self.public_inputs.recipient_commitment);
        bytes.extend_from_slice(&self.public_inputs.amount.to_le_bytes());

        bytes
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, Groth16Error> {
        if data.len() < 4 {
            return Err(Groth16Error::SerializationError(
                "Data too short".to_string(),
            ));
        }

        let mut offset = 0;
        let proof_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        offset += 4;

        if offset + proof_len + 128 > data.len() {
            return Err(Groth16Error::SerializationError(
                "Insufficient data".to_string(),
            ));
        }

        let proof = data[offset..offset + proof_len].to_vec();
        offset += proof_len;

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut root = [0u8; 32];
        root.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut recipient_commitment = [0u8; 32];
        recipient_commitment.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let amount = u128::from_le_bytes(
            data[offset..offset + 16]
                .try_into()
                .map_err(|_| Groth16Error::SerializationError("Invalid amount".to_string()))?,
        );

        Ok(Groth16Proof {
            proof,
            public_inputs: TransferPublicInputs {
                commitment,
                nullifier,
                root,
                recipient_commitment,
                amount,
            },
        })
    }

    /// Get proof size
    pub fn size(&self) -> usize {
        self.proof.len()
    }
}

/// Groth16 Proof Generator
pub struct Groth16Generator {
    /// Mock verification key
    vk: Vec<u8>,
    /// Mock proving key
    pk: Vec<u8>,
}

impl Groth16Generator {
    /// Create new generator
    /// In production: loads actual VK and PK from trusted setup
    pub fn new() -> Result<Self, Groth16Error> {
        log::info!("Initializing Groth16 generator (BLS12-381)");

        Ok(Self {
            vk: vec![0u8; 256],  // Mock VK
            pk: vec![0u8; 1024], // Mock PK
        })
    }

    /// Generate Groth16 proof for transfer
    pub fn prove_transfer(
        &self,
        witness: &TransferWitness,
        recipient: [u8; 32],
    ) -> Result<Groth16Proof, Groth16Error> {
        log::info!("Generating Groth16 transfer proof");

        // Validate witness
        witness.validate()?;

        // Compute public inputs
        let public_inputs = TransferPublicInputs::from_witness(witness, recipient)?;

        log::debug!(
            "Public inputs: commitment={:?}, nullifier={:?}",
            hex::encode(&public_inputs.commitment[..4]),
            hex::encode(&public_inputs.nullifier[..4])
        );

        // In production:
        // 1. Run the constraint circuit with witness
        // 2. Generate QAP witness
        // 3. Compute proof points (A, B, C) on BLS12-381
        // 4. Return serialized proof

        // For now: generate mock proof
        let proof_data = self.generate_mock_proof(&public_inputs)?;

        Ok(Groth16Proof {
            proof: proof_data,
            public_inputs,
        })
    }

    /// Generate mock proof (for testing)
    fn generate_mock_proof(
        &self,
        public_inputs: &TransferPublicInputs,
    ) -> Result<Vec<u8>, Groth16Error> {
        use sha2::{Sha256, Digest};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut proof = vec![0u8; 96]; // Standard Groth16 proof size

        // Mix in public inputs to create deterministic but unique proof
        let mut hasher = Sha256::new();
        hasher.update(&public_inputs.commitment);
        hasher.update(&public_inputs.nullifier);
        hasher.update(&public_inputs.root);

        let hash = hasher.finalize();

        // Copy hash into proof
        proof[0..32].copy_from_slice(&hash);

        // Add randomness for remaining bytes (in production: actual proof points)
        for i in 32..96 {
            proof[i] = rng.gen();
        }

        Ok(proof)
    }

    /// Get verification key
    pub fn verification_key(&self) -> &[u8] {
        &self.vk
    }

    /// Get proving key size
    pub fn proving_key_size(&self) -> usize {
        self.pk.len()
    }
}

impl Default for Groth16Generator {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

      fn create_test_witness() -> TransferWitness {
        TransferWitness {
            secret: [1u8; 32],
            randomness: [2u8; 32],
            amount: 1000,
            merkle_path: vec![[3u8; 32]; 20],  
            merkle_indices: {
                let mut v = Vec::new();
                for i in 0..20 {
                    v.push(i % 2 == 0);  
                }
                v
            },
        }
    }
    #[test]
    fn test_witness_validation() {
        let witness = create_test_witness();
        assert!(witness.validate().is_ok());
    }

    #[test]
    fn test_commitment_computation() {
        let witness = create_test_witness();
        let commitment = witness.compute_commitment();
        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_nullifier_computation() {
        let witness = create_test_witness();
        let nullifier = witness.compute_nullifier();
        assert_ne!(nullifier, [0u8; 32]);
    }

    #[test]
    fn test_public_inputs_creation() {
        let witness = create_test_witness();
        let public_inputs = TransferPublicInputs::from_witness(&witness, [4u8; 32]);
        assert!(public_inputs.is_ok());

        let inputs = public_inputs.unwrap();
        assert_eq!(inputs.amount, 1000);
    }

    #[test]
      fn test_groth16_proof_generation() {
        let generator = Groth16Generator::new().unwrap();
        let witness = create_test_witness();

        let proof = generator.prove_transfer(&witness, [4u8; 32]);
        assert!(proof.is_ok());

        let p = proof.unwrap();
        assert_eq!(p.proof.len(), 96);
        assert_ne!(p.public_inputs.commitment, [0u8; 32]);  
    }

    #[test]
    fn test_proof_serialization() {
        let generator = Groth16Generator::new().unwrap();
        let witness = create_test_witness();

        let proof = generator.prove_transfer(&witness, [4u8; 32]).unwrap();
        let serialized = proof.to_bytes();

        let deserialized = Groth16Proof::from_bytes(&serialized);
        assert!(deserialized.is_ok());

        let p2 = deserialized.unwrap();
        assert_eq!(p2.proof, proof.proof);
        assert_eq!(p2.public_inputs.amount, proof.public_inputs.amount);
    }

    #[test]
    fn test_invalid_witness() {
        let mut witness = create_test_witness();
        witness.secret = [0u8; 32]; // Invalid

        let result = witness.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_circuit_satisfiability() {
        // Verify the real TransferCircuit (with Poseidon constraints) is satisfiable
        // for a valid witness. This uses ConstraintSystem directly (no Groth16 setup)
        // so it completes in milliseconds even for MAX_INPUTS=8, TREE_DEPTH=32.
        use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
        use ark_bn254::Fr;
        use transfer_circuit::TransferCircuit;

        let circuit = TransferCircuit::test_circuit();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("constraint generation must not fail");

        assert!(
            cs.is_satisfied().expect("is_satisfied must not fail"),
            "TransferCircuit::test_circuit() must satisfy all Poseidon constraints"
        );

        println!("TransferCircuit constraint count: {}", cs.num_constraints());
    }
}