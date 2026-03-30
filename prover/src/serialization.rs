//! Serialization functions matching zk-types interface contract
//!
//! CRITICAL: Output byte layout MUST match what pallet-proof-verifier expects

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zk_types::{
    Groth16Proof, TransferPublicInputs, ProofSubmission,
    G1_UNCOMPRESSED_SIZE, G2_UNCOMPRESSED_SIZE,
    Hash256, AssetId, NATIVE_ASSET_ID,
};

/// Serialize arkworks Groth16 proof to zk-types format
/// 
/// # Layout
/// - `a`: 64 bytes (G1 uncompressed)  
/// - `b`: 128 bytes (G2 uncompressed)
/// - `c`: 64 bytes (G1 uncompressed)
/// 
/// Total: 256 bytes
pub fn serialize_groth16_proof(proof: &Proof<Bn254>) -> Groth16Proof {
    let mut a_bytes = [0u8; G1_UNCOMPRESSED_SIZE];
    let mut b_bytes = [0u8; G2_UNCOMPRESSED_SIZE];
    let mut c_bytes = [0u8; G1_UNCOMPRESSED_SIZE];
    
    // IMPORTANT: Use uncompressed serialization
    proof.a.serialize_uncompressed(&mut a_bytes[..])
        .expect("G1 point serialization should not fail");
    proof.b.serialize_uncompressed(&mut b_bytes[..])
        .expect("G2 point serialization should not fail");
    proof.c.serialize_uncompressed(&mut c_bytes[..])
        .expect("G1 point serialization should not fail");
    
    Groth16Proof {
        a: a_bytes,
        b: b_bytes,
        c: c_bytes,
    }
}

/// Deserialize zk-types proof back to arkworks format
pub fn deserialize_groth16_proof(proof: &Groth16Proof) -> Result<Proof<Bn254>, String> {
    let a = G1Affine::deserialize_uncompressed(&proof.a[..])
        .map_err(|e| format!("Invalid G1 point a: {:?}", e))?;
    let b = G2Affine::deserialize_uncompressed(&proof.b[..])
        .map_err(|e| format!("Invalid G2 point b: {:?}", e))?;
    let c = G1Affine::deserialize_uncompressed(&proof.c[..])
        .map_err(|e| format!("Invalid G1 point c: {:?}", e))?;
    
    Ok(Proof { a, b, c })
}

/// Convert Fr to 32-byte array (little-endian)
pub fn fr_to_bytes(fr: &Fr) -> Hash256 {
    let mut bytes = [0u8; 32];
    fr.serialize_uncompressed(&mut bytes[..])
        .expect("Fr serialization should not fail");
    bytes
}

/// Convert 32-byte array to Fr
pub fn bytes_to_fr(bytes: &Hash256) -> Result<Fr, String> {
    Fr::deserialize_uncompressed(&bytes[..])
        .map_err(|e| format!("Invalid field element: {:?}", e))
}

/// Serialize transfer public inputs
pub fn serialize_transfer_inputs(
    merkle_root: Fr,
    nullifiers: Vec<Fr>,
    output_commitments: Vec<Fr>,
    asset_id: AssetId,
    fee_commitment: Fr,
) -> TransferPublicInputs {
    TransferPublicInputs {
        merkle_root: fr_to_bytes(&merkle_root),
        nullifiers: nullifiers.iter().map(fr_to_bytes).collect(),
        output_commitments: output_commitments.iter().map(fr_to_bytes).collect(),
        asset_id,
        fee_commitment: fr_to_bytes(&fee_commitment),
    }
}

/// Create complete ProofSubmission for shielded transfer
pub fn create_transfer_submission(
    proof: &Proof<Bn254>,
    merkle_root: Fr,
    nullifiers: Vec<Fr>,
    output_commitments: Vec<Fr>,
    asset_id: AssetId,
    fee_commitment: Fr,
) -> ProofSubmission {
    ProofSubmission::ShieldedTransfer {
        proof: serialize_groth16_proof(proof),
        inputs: serialize_transfer_inputs(
            merkle_root,
            nullifiers,
            output_commitments,
            asset_id,
            fee_commitment,
        ),
    }
}

/// Serialize verifying key for on-chain storage
pub fn serialize_verifying_key(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    let mut bytes = Vec::new();
    vk.serialize_uncompressed(&mut bytes)
        .expect("VK serialization should not fail");
    bytes
}

/// Deserialize verifying key from bytes
pub fn deserialize_verifying_key(bytes: &[u8]) -> Result<VerifyingKey<Bn254>, String> {
    VerifyingKey::deserialize_uncompressed(bytes)
        .map_err(|e| format!("Invalid verifying key: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::rngs::OsRng;
    use ark_ff::UniformRand;
    
    #[test]
    fn test_proof_roundtrip() {
        let mut rng = OsRng;
        
        // Create random proof (not valid, just for serialization test)
        let proof = Proof {
            a: G1Affine::rand(&mut rng),
            b: G2Affine::rand(&mut rng),
            c: G1Affine::rand(&mut rng),
        };
        
        // Serialize
        let serialized = serialize_groth16_proof(&proof);
        
        // Check sizes
        assert_eq!(serialized.a.len(), 64);
        assert_eq!(serialized.b.len(), 128);
        assert_eq!(serialized.c.len(), 64);
        
        // Deserialize
        let deserialized = deserialize_groth16_proof(&serialized).unwrap();
        
        // Verify roundtrip
        assert_eq!(proof.a, deserialized.a);
        assert_eq!(proof.b, deserialized.b);
        assert_eq!(proof.c, deserialized.c);
    }
    
    #[test]
    fn test_fr_roundtrip() {
        let mut rng = OsRng;
        let fr = Fr::rand(&mut rng);
        
        let bytes = fr_to_bytes(&fr);
        let recovered = bytes_to_fr(&bytes).unwrap();
        
        assert_eq!(fr, recovered);
    }
    
    #[test]
    fn test_submission_encoding() {
        use codec::Encode;
        
        let mut rng = OsRng;
        let proof = Proof {
            a: G1Affine::rand(&mut rng),
            b: G2Affine::rand(&mut rng),
            c: G1Affine::rand(&mut rng),
        };
        
        let submission = create_transfer_submission(
            &proof,
            Fr::rand(&mut rng),
            vec![Fr::rand(&mut rng)],
            vec![Fr::rand(&mut rng)],
            NATIVE_ASSET_ID,
            Fr::rand(&mut rng),
        );
        
        let encoded = submission.encode();
        assert!(!encoded.is_empty());
        println!("ProofSubmission encoded size: {} bytes", encoded.len());
    }
}