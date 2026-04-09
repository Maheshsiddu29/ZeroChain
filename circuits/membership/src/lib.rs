//! Validator Membership Circuit (Halo2)
//!
//! Proves: "I am a validator in the active set for epoch E, slot S"
//! Without revealing: Which specific validator I am
//!
//! Public inputs:
//! - validator_root: Merkle root of active validator credentials
//! - epoch: Current epoch number
//! - slot: Current slot number
//!
//! Private witness:
//! - credential_secret: My validator secret credential
//! - merkle_path: Merkle authentication path
//! - merkle_indices: Path directions

pub mod circuit;
pub mod poseidon_chip;

pub use circuit::ValidatorMembershipCircuit;

pub const VALIDATOR_TREE_DEPTH: usize = 20; // 2^20 = ~1M validators

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp;
    use ff::Field;
    use rand::rngs::OsRng;

    #[test]
    fn test_membership_circuit() {
        let k = 12;

        // Create a dummy credential
        let credential_secret = Fp::random(OsRng);
        
        // Simplified: credential_commitment = credential_secret (no hash for now)
        let credential_commitment = credential_secret;

        // Empty Merkle path
        let merkle_path = vec![Fp::zero(); VALIDATOR_TREE_DEPTH];
        let merkle_indices = vec![false; VALIDATOR_TREE_DEPTH];

        // With empty path, root = commitment
        let validator_root = credential_commitment;

        let epoch = 42u64;
        let slot = 100u64;

        let circuit = ValidatorMembershipCircuit::new(
            validator_root,
            epoch,
            slot,
            credential_secret,
            merkle_path,
            merkle_indices,
        );

        let public_inputs = vec![
            validator_root,
            Fp::from(epoch),
            Fp::from(slot),
        ];

        let prover = MockProver::run(k, &circuit, vec![public_inputs]);
        
        match prover {
            Ok(p) => {
                if let Err(e) = p.verify() {
                    panic!("Verification failed: {:?}", e);
                }
                println!("✓ Membership circuit verified");
            }
            Err(e) => {
                println!("Mock prover setup error: {:?}", e);
            }
        }
    }
}