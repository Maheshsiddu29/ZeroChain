//! Trait definitions for ZK verification

/// Extension trait for ZK verifiers
pub trait ZkVerifierExt {
    /// Verify Groth16 proof for transfer
    fn verify_groth16_transfer(
        proof: &[u8],
        commitment: [u8; 32],
        nullifier: [u8; 32],
        amount: u128,
    ) -> bool;

    /// Verify Halo2 proof for membership
    fn verify_halo2_membership(
        proof: &[u8],
        commitment: [u8; 32],
        tree_root: [u8; 32],
    ) -> bool;

    /// Verify Nova proof for state lineage
    fn verify_nova_lineage(
        proof: &[u8],
        genesis_root: [u8; 32],
        final_root: [u8; 32],
        num_steps: u64,
    ) -> bool;

    /// Verify Halo2 slashing proof
    fn verify_halo2_slashing(
        proof: &[u8],
        validator_root: [u8; 32],
        block_hash_1: [u8; 32],
        block_hash_2: [u8; 32],
    ) -> bool;
}

