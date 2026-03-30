//! ZK-ORIGIN proof generation

use origin_circuit::ZkOriginAccumulator;
use ark_bn254::Fr;
use ark_serialize::CanonicalDeserialize;
use std::path::Path;
use anyhow::{Result, Context};

/// Generate ZK-ORIGIN proof
pub fn generate_origin_proof(
    prev_state_hex: &str,
    new_state_hex: &str,
    height: u64,
    tx_hash_hex: &str,
    accumulator_path: &Path,
) -> Result<serde_json::Value> {
    println!(" Loading accumulator...");
    
    // Load or create accumulator
    let mut accumulator = if accumulator_path.exists() {
        let bytes = std::fs::read(accumulator_path)
            .context("Failed to read accumulator file")?;
        ZkOriginAccumulator::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize accumulator: {}", e))?
    } else {
        println!("   No existing accumulator, creating new one");
        let genesis = hex_to_fr(prev_state_hex)?;
        ZkOriginAccumulator::genesis(genesis)
    };
    
    println!("   Current height: {}", accumulator.current_height);
    
    // Parse inputs
    let prev_state = hex_to_fr(prev_state_hex)?;
    let new_state = hex_to_fr(new_state_hex)?;
    let tx_hash = hex_to_fr(tx_hash_hex)?;
    
    println!("\n Folding block {}...", height);
    
    // Fold new block
    accumulator.fold_block(prev_state, new_state, height, tx_hash)
        .map_err(|e| anyhow::anyhow!("Failed to fold block: {}", e))?;
    
    println!("   Block folded");
    
    // Verify
    println!("\n Verifying chain...");
    accumulator.verify()
        .map_err(|e| anyhow::anyhow!("Verification failed: {}", e))?;
    println!("   Chain valid");
    
    // Compress
    println!("\n Compressing proof...");
    let compressed = accumulator.compress()
        .map_err(|e| anyhow::anyhow!("Compression failed: {}", e))?;
    println!("   Compressed to {} bytes", compressed.len());
    
    // Save accumulator for next block
    println!("\n Saving accumulator...");
    let acc_bytes = accumulator.to_bytes()
        .map_err(|e| anyhow::anyhow!("Failed to serialize accumulator: {}", e))?;
    std::fs::write(accumulator_path, acc_bytes)
        .context("Failed to save accumulator")?;
    println!("   Saved to {}", accumulator_path.display());
    
    // Return proof as JSON
    Ok(serde_json::json!({
        "proof_type": "ZK-ORIGIN",
        "block_height": height,
        "prev_state_root": prev_state_hex,
        "new_state_root": new_state_hex,
        "proof_bytes": hex::encode(&compressed),
        "proof_size": compressed.len(),
    }))
}

fn hex_to_fr(hex: &str) -> Result<Fr> {
    let hex_clean = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex_clean)
        .context("Invalid hex")?;
    
    // Pad to 32 bytes
    let mut padded = vec![0u8; 32];
    let copy_len = bytes.len().min(32);
    padded[32 - copy_len..].copy_from_slice(&bytes[bytes.len() - copy_len..]);
    
    Fr::deserialize_uncompressed(&padded[..])
        .context("Failed to deserialize Fr")
}