//! Example: Generate ZK-ORIGIN proof programmatically

use ark_bn254::Fr;
use ark_ff::PrimeField;
use prover::origin_prover::{StateTransition, OriginProof};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZK-ORIGIN Lineage Proof Example ===\n");

    let genesis_root = [0x01u8; 32];
    let genesis_fr = Fr::from_le_bytes_mod_order(&genesis_root);

    println!("Genesis root: {}\n", hex::encode(&genesis_root));

    let mut transitions = Vec::new();
    let mut current_root = genesis_fr;

    for block_num in 1..=10 {
        let next_root = Fr::from(block_num as u64 + 1000);

        transitions.push(StateTransition::new(current_root, next_root, block_num));

        current_root = next_root;
    }

    println!("Generating proof...");
    let proof = OriginProof::generate(transitions, genesis_root)?;

    println!("\n{}", proof);

    proof.verify()?;
    proof.reject_if_tampered()?;

    println!("\n✓ Proof verified successfully!");

    Ok(())
}