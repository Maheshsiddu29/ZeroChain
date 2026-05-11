//! Groth16 Prover Implementation
//! 
//! Generates zero-knowledge proofs for shielded transfers using Groth16 over BN254

use ark_bn254::Bn254;
use ark_ff::{PrimeField, BigInteger};
use ark_groth16::{Proof, VerifyingKey};
use ark_bn254::Fr;
use anyhow::Result;
use std::path::Path;
use std::fs;

/// Convert Fr to 32 bytes (little-endian)
pub fn fr_to_bytes(fr: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let bigint = fr.into_bigint();
    let le_bytes = bigint.to_bytes_le();
    let copy_len = le_bytes.len().min(32);
    bytes[..copy_len].copy_from_slice(&le_bytes[..copy_len]);
    bytes
}

/// Convert 32 bytes to Fr (little-endian)
pub fn bytes_to_fr(bytes: &[u8; 32]) -> Result<Fr> {
    Ok(Fr::from_le_bytes_mod_order(bytes))
}

/// Serialize a Groth16 proof to bytes
/// 
/// Groth16 proof format (on BN254):
/// - A: 2 field elements = 64 bytes
/// - B: 4 field elements = 128 bytes  
/// - C: 2 field elements = 64 bytes
/// Total: 256 bytes (compressed)
pub fn proof_to_bytes(proof: &Proof<Bn254>) -> Result<Vec<u8>> {
    use ark_serialize::CanonicalSerialize;
    
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes)
        .map_err(|e| anyhow::anyhow!("Failed to serialize Groth16 proof: {:?}", e))?;
    Ok(bytes)
}

/// Deserialize a Groth16 proof from bytes
pub fn bytes_to_proof(bytes: &[u8]) -> Result<Proof<Bn254>> {
    use ark_serialize::CanonicalDeserialize;
    
    Proof::<Bn254>::deserialize_compressed(bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize Groth16 proof: {:?}", e))
}

/// Serialize verifying key to bytes
pub fn vk_to_bytes(vk: &VerifyingKey<Bn254>) -> Result<Vec<u8>> {
    use ark_serialize::CanonicalSerialize;
    
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)
        .map_err(|e| anyhow::anyhow!("Failed to serialize verifying key: {:?}", e))?;
    Ok(bytes)
}

/// Deserialize verifying key from bytes
pub fn bytes_to_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>> {
    use ark_serialize::CanonicalDeserialize;
    
    VerifyingKey::<Bn254>::deserialize_compressed(bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize verifying key: {:?}", e))
}

/// Public inputs for a shielded transfer
#[derive(Clone, Debug)]
pub struct TransferPublicInputs {
    pub merkle_root: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub output_commitments: Vec<[u8; 32]>,
    pub asset_id: [u8; 32],
    pub fee_commitment: [u8; 32],
}

impl TransferPublicInputs {
    /// Serialize public inputs to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Merkle root
        bytes.extend_from_slice(&self.merkle_root);
        
        // Nullifiers count and data
        bytes.push(self.nullifiers.len() as u8);
        for nullifier in &self.nullifiers {
            bytes.extend_from_slice(nullifier);
        }
        
        // Output commitments count and data
        bytes.push(self.output_commitments.len() as u8);
        for commitment in &self.output_commitments {
            bytes.extend_from_slice(commitment);
        }
        
        // Asset ID
        bytes.extend_from_slice(&self.asset_id);
        
        // Fee commitment
        bytes.extend_from_slice(&self.fee_commitment);
        
        bytes
    }

    /// Deserialize public inputs from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 130 {
            anyhow::bail!("Public inputs too short");
        }

        let mut offset = 0;

        // Merkle root
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Nullifiers
        let nullifier_count = bytes[offset] as usize;
        offset += 1;
        let mut nullifiers = Vec::new();
        for _ in 0..nullifier_count {
            let mut nullifier = [0u8; 32];
            nullifier.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;
            nullifiers.push(nullifier);
        }

        // Output commitments
        let commitment_count = bytes[offset] as usize;
        offset += 1;
        let mut output_commitments = Vec::new();
        for _ in 0..commitment_count {
            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;
            output_commitments.push(commitment);
        }

        // Asset ID
        let mut asset_id = [0u8; 32];
        asset_id.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        // Fee commitment
        let mut fee_commitment = [0u8; 32];
        fee_commitment.copy_from_slice(&bytes[offset..offset + 32]);

        Ok(TransferPublicInputs {
            merkle_root,
            nullifiers,
            output_commitments,
            asset_id,
            fee_commitment,
        })
    }
}

/// Generate transfer proof stub
/// 
/// In production, this would:
/// 1. Load witness from witness_file
/// 2. Load proving key
/// 3. Generate Groth16 proof
/// 4. Serialize and save to output_file
pub fn generate_transfer_proof(
    witness_file: &Path,
    output_file: &Path,
) -> Result<()> {
    // Read witness
    let witness_data = fs::read_to_string(witness_file)?;
    log::info!("📄 Loaded witness from {}", witness_file.display());
    log::info!("   Witness size: {} bytes", witness_data.len());

    // TODO: Parse JSON witness and call actual Groth16 prover
    // For now, create placeholder proof (256 bytes for Groth16 on BN254)
    let placeholder_proof = vec![0u8; 256];

    // Save proof
    fs::write(output_file, &placeholder_proof)?;
    log::info!("💾 Proof saved to {} ({} bytes)", 
        output_file.display(), 
        placeholder_proof.len()
    );

    Ok(())
}

/// Verify transfer proof stub
/// 
/// In production, this would:
/// 1. Load proof from proof_file
/// 2. Load verifying key from vk_file
/// 3. Call Groth16 verification
/// 4. Return verification result
pub fn verify_transfer_proof(
    proof_file: &Path,
    vk_file: &Path,
) -> Result<bool> {
    let proof_data = fs::read(proof_file)?;
    let _vk_data = fs::read(vk_file)?;

    log::info!("🔍 Verifying proof ({} bytes)", proof_data.len());

    // TODO: Implement actual verification
    // For now, return placeholder
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fr_roundtrip() {
        let fr = Fr::from(42u64);
        let bytes = fr_to_bytes(&fr);
        let fr2 = bytes_to_fr(&bytes).unwrap();
        assert_eq!(fr, fr2);
    }

    #[test]
    fn test_transfer_inputs_roundtrip() {
        let inputs = TransferPublicInputs {
            merkle_root: [0x01u8; 32],
            nullifiers: vec![[0x02u8; 32]],
            output_commitments: vec![[0x03u8; 32]],
            asset_id: [0x04u8; 32],
            fee_commitment: [0x05u8; 32],
        };

        let bytes = inputs.to_bytes();
        let inputs2 = TransferPublicInputs::from_bytes(&bytes).unwrap();

        assert_eq!(inputs.merkle_root, inputs2.merkle_root);
        assert_eq!(inputs.asset_id, inputs2.asset_id);
        assert_eq!(inputs.fee_commitment, inputs2.fee_commitment);
    }
}