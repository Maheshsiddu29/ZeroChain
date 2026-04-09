//! ZK-ORIGIN proof generation
//!
//! Currently uses a placeholder since Nova requires ark 0.5.x

use ark_bn254::Fr;
use ark_ff::{PrimeField, BigInteger};
use std::path::Path;
use anyhow::{Result, Context};

// Import the step circuit (which is what origin_circuit currently exports)
use origin_circuit::step_circuit::StateTransitionCircuit;

/// Generate ZK-ORIGIN proof
///
/// Currently produces a placeholder proof since Nova IVC requires
/// ark 0.5.x but the workspace uses ark 0.4.x.
pub fn generate_origin_proof(
    prev_state_hex: &str,
    new_state_hex: &str,
    height: u64,
    tx_hash_hex: &str,
    accumulator_path: &Path,
) -> Result<serde_json::Value> {
    log::info!("Generating ZK-ORIGIN proof...");

    // Parse inputs
    let prev_state = hex_to_fr(prev_state_hex)?;
    let new_state = hex_to_fr(new_state_hex)?;
    let _tx_hash = hex_to_fr(tx_hash_hex)?;

    log::info!("  Block height: {}", height);
    log::info!("  Prev state: {}", prev_state_hex);
    log::info!("  New state: {}", new_state_hex);

    // Create the step circuit (for future Nova integration)
    let _step = StateTransitionCircuit::new(prev_state, new_state, height);

    // Build placeholder proof data
    let mut proof_bytes = Vec::new();
    proof_bytes.extend_from_slice(&height.to_le_bytes());
    proof_bytes.extend_from_slice(&prev_state.into_bigint().to_bytes_le());
    proof_bytes.extend_from_slice(&new_state.into_bigint().to_bytes_le());

    // Save accumulator state
    if let Some(parent) = accumulator_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(accumulator_path, &proof_bytes)
        .context("Failed to save accumulator")?;

    log::info!("  Proof size: {} bytes (placeholder)", proof_bytes.len());
    log::warn!("  Note: Full Nova IVC not yet implemented (requires ark 0.5.x)");

    Ok(serde_json::json!({
        "proof_type": "ZK-ORIGIN",
        "status": "placeholder",
        "block_height": height,
        "prev_state_root": prev_state_hex,
        "new_state_root": new_state_hex,
        "proof_bytes": hex::encode(&proof_bytes),
        "proof_size": proof_bytes.len(),
        "note": "Full Nova IVC pending ark version upgrade"
    }))
}

fn hex_to_fr(hex: &str) -> Result<Fr> {
    let hex_clean = hex.trim_start_matches("0x");

    if hex_clean.is_empty() || hex_clean == "0" {
        return Ok(Fr::from(0u64));
    }

    let bytes = hex::decode(hex_clean).context("Invalid hex")?;

    let mut padded = [0u8; 32];
    let copy_len = bytes.len().min(32);
    padded[..copy_len].copy_from_slice(&bytes[..copy_len]);

    Ok(Fr::from_le_bytes_mod_order(&padded))
}