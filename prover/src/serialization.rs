//! Proof serialization and submission encoding

use ark_bn254::Fr;
use ark_ff::{PrimeField, BigInteger};
use anyhow::{Result, Context};

use crate::groth16_prover;

/// Convert Fr to 32 bytes (little-endian)
fn fr_to_bytes(fr: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let bigint = fr.into_bigint();
    let le_bytes = bigint.to_bytes_le();
    let copy_len = le_bytes.len().min(32);
    bytes[..copy_len].copy_from_slice(&le_bytes[..copy_len]);
    bytes
}

/// Convert 32 bytes to Fr (little-endian)
fn bytes_to_fr(bytes: &[u8; 32]) -> Result<Fr> {
    Ok(Fr::from_le_bytes_mod_order(bytes))
}

/// Create a transfer submission from arkworks proof and public inputs.
pub fn create_transfer_submission(
    proof: &ark_groth16::Proof<ark_bn254::Bn254>,
    public_inputs: &[Fr],
) -> Result<Vec<u8>> {
    use codec::Encode;

    // Convert arkworks proof to zk-types format
    let zk_proof = groth16_prover::proof_to_zk_types(proof)?;

    // Build public inputs structure
    let mut merkle_root = [0u8; 32];
    let mut nullifiers = Vec::new();
    let mut output_commitments = Vec::new();
    let mut asset_id = [0u8; 32];
    let mut fee_commitment = [0u8; 32];

    if !public_inputs.is_empty() {
        merkle_root = fr_to_bytes(&public_inputs[0]);

        // Assume structure: merkle_root, nullifiers..., output_commitments..., asset_id, fee_commitment
        // For now assume 1 nullifier, 1 output commitment (simplest case)
        if public_inputs.len() >= 5 {
            nullifiers.push(fr_to_bytes(&public_inputs[1]));
            output_commitments.push(fr_to_bytes(&public_inputs[2]));
            asset_id = fr_to_bytes(&public_inputs[3]);
            fee_commitment = fr_to_bytes(&public_inputs[4]);
        }
    }

    let inputs = zk_types::TransferPublicInputs {
        merkle_root,
        nullifiers,
        output_commitments,
        asset_id,
        fee_commitment,
    };

    let data = zk_types::ShieldedTransferData {
        proof: zk_proof,
        inputs,
    };

    let submission = zk_types::ProofSubmission::ShieldedTransfer(Box::new(data));

    Ok(submission.encode())
}

/// Parse a transfer submission to extract proof and public inputs
pub fn parse_transfer_submission(
    submission_bytes: &[u8],
) -> Result<(ark_groth16::Proof<ark_bn254::Bn254>, Vec<Fr>)> {
    use codec::Decode;

    let submission = zk_types::ProofSubmission::decode(&mut &submission_bytes[..])
        .context("Failed to decode submission")?;

    match submission {
        zk_types::ProofSubmission::ShieldedTransfer(data) => {
            // Convert zk-types proof back to arkworks
            let proof = groth16_prover::zk_types_to_proof(&data.proof)?;

            // Reconstruct public inputs
            let mut public_inputs = Vec::new();

            public_inputs.push(bytes_to_fr(&data.inputs.merkle_root)?);

            for nullifier in &data.inputs.nullifiers {
                public_inputs.push(bytes_to_fr(nullifier)?);
            }

            for commitment in &data.inputs.output_commitments {
                public_inputs.push(bytes_to_fr(commitment)?);
            }

            public_inputs.push(bytes_to_fr(&data.inputs.asset_id)?);
            public_inputs.push(bytes_to_fr(&data.inputs.fee_commitment)?);

            Ok((proof, public_inputs))
        }
        _ => anyhow::bail!("Expected ShieldedTransfer submission"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_fr_roundtrip() {
        let mut rng = test_rng();
        let fr = Fr::rand(&mut rng);
        let bytes = fr_to_bytes(&fr);
        let fr2 = bytes_to_fr(&bytes).unwrap();
        assert_eq!(fr, fr2);
    }
}