//! `set-vk` command — upload the Groth16 transfer verifying key via sudo.

use crate::chain::{parse_signer, ChainClient};
use crate::commands::SetVkOpts;
use anyhow::{Context, Result};
use std::fs;

pub async fn handle_set_vk(opts: SetVkOpts, rpc_endpoint: &str) -> Result<()> {
    let vk_bytes = fs::read(&opts.vk)
        .with_context(|| format!("cannot read VK file: {}", opts.vk.display()))?;

    if vk_bytes.is_empty() {
        anyhow::bail!("VK file is empty: {}", opts.vk.display());
    }

    println!("Setting verifying key...");
    println!("  File:  {}", opts.vk.display());
    println!("  Size:  {} bytes", vk_bytes.len());

    let signer_keypair = parse_signer(&opts.signer)
        .map_err(|e| anyhow::anyhow!("--signer: {}", e))?;
    let client = ChainClient::connect(rpc_endpoint, signer_keypair).await?;

    client
        .set_verifying_key("Groth16Transfer", &vk_bytes)
        .await?;

    // Read back to confirm storage was updated.
    let stored_len = client.get_verifying_key_len("Groth16Transfer").await?;
    if stored_len != vk_bytes.len() as u64 {
        anyhow::bail!(
            "VK size mismatch after upload: submitted {} bytes but chain stores {} bytes",
            vk_bytes.len(),
            stored_len,
        );
    }

    println!();
    println!("Verifying key set successfully!");
    println!("  ProofVerifier::VerifyingKeys(Groth16Transfer) = {} bytes", stored_len);

    Ok(())
}
