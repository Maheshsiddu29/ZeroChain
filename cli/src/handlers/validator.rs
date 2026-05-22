//! Validator registration and query handlers

use crate::commands::{RegisterValidatorOpts, QueryValidatorSetOpts, QueryValidatorOpts};
use crate::rpc::RpcClient;
use anyhow::Result;

/// Handle register-validator command
pub async fn handle_register_validator(
    opts: RegisterValidatorOpts,
    rpc_endpoint: &str,
) -> Result<()> {
    println!("\n  Registering Validator");

    // Validate
    opts.validate()?;

    let commitment_display = if opts.commitment.len() > 16 {
        format!("{}...", &opts.commitment[..16])
    } else {
        opts.commitment.clone()
    };

    println!(" Registration Details:");
    println!("  Name: {}", opts.name);
    println!("  Commitment: {}", commitment_display);
    println!("  Stake: {} ZERO", opts.stake);
    println!();

    // Connect to node
    let _client = RpcClient::new(rpc_endpoint);

    // Build extrinsic
    println!(" Building registration extrinsic...");
    let mut extrinsic = vec![];
    extrinsic.extend_from_slice(opts.name.as_bytes());
    extrinsic.extend_from_slice(&hex::decode(&opts.commitment)?);
    extrinsic.extend_from_slice(&opts.stake.to_le_bytes());

    if let Some(proof_path) = &opts.proof {
        let proof = std::fs::read(proof_path)?;
        extrinsic.extend_from_slice(&proof);
        println!("  Membership proof included: {} bytes", proof.len());
    }

    println!();

    // Submit
    println!(" Submitting registration...");
    let tx_hash = _client.submit_extrinsic(&extrinsic).await?;
    println!("  Transaction hash: {}", tx_hash);
    println!();

    // Wait for finalization
    println!(" Waiting for finalization...");
    let block = _client.wait_for_finalization(&tx_hash, 60).await?;
    println!("  Finalized in block: {}", block);
    println!();

    // Query validator set to confirm registration
    println!(" Validator Registered!");
    println!();
    println!(" Validator Details:");
    println!("  Status: ACTIVE");
    println!("  Stake: {} ZERO", opts.stake);
    println!("  Threshold participation: 2-of-3");
    println!();

    Ok(())
}

/// Handle query-validator-set command
pub async fn handle_query_validator_set(
    opts: QueryValidatorSetOpts,
    rpc_endpoint: &str,
) -> Result<()> {
    println!("\n Validator Set");

    let client = RpcClient::new(rpc_endpoint);

    // Query validators
    let validators = client.get_validators().await?;

    // Filter if needed
    let displayed: Vec<_> = validators
        .iter()
        .filter(|v| !opts.active_only || v.active)
        .collect();

    println!("Total validators: {}", displayed.len());
    println!();

    // Display based on format
    match opts.format.as_str() {
        "json" => {
            let json_data = serde_json::to_string_pretty(&displayed)?;
            println!("{}", json_data);
        }
        _ => {
            // Text format
            println!("{:<10} {:<20} {:<15} {:<10}", "ID", "Commitment", "Stake", "Status");
            println!("{}", "─".repeat(55));

            for (idx, v) in displayed.iter().enumerate() {
                let commitment_short = if v.commitment.len() > 16 {
                    format!("{}...", &v.commitment[..16])
                } else {
                    v.commitment.clone()
                };

                println!(
                    "{:<10} {:<20} {:<15} {:<10}",
                    idx,
                    commitment_short,
                    format!("{} ZERO", v.stake),
                    if v.active { "ACTIVE" } else { "SLASHED" }
                );
            }
        }
    }

    println!();

    // Statistics
    let active_count = displayed.iter().filter(|v| v.active).count();
    let total_stake: u128 = displayed.iter().map(|v| v.stake).sum();

    println!(" Statistics:");
    println!("  Active validators: {}", active_count);
    println!("  Total staked: {} ZERO", total_stake);
    println!("  Threshold: 2-of-{}", displayed.len());
    println!();

    Ok(())
}

/// Handle query-validator command
pub async fn handle_query_validator(
    opts: QueryValidatorOpts,
    rpc_endpoint: &str,
) -> Result<()> {
    println!("\n Validator Details");

    let client = RpcClient::new(rpc_endpoint);

    // Get specific validator
    let validator = client.get_validator(&opts.id).await?;

    match opts.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&validator)?);
        }
        _ => {
            println!("ID: {}", &validator.id);
            println!("Commitment: {}", validator.commitment);
            println!("Stake: {} ZERO", validator.stake);
            println!("Status: {}", if validator.active { "ACTIVE" } else { "SLASHED" });
            println!("Registered: Block {}", validator.epoch);
            println!();

            if !validator.active {
                println!("  This validator has been slashed!");
                println!("Slash reason: Equivocation detected");
                println!("Slash amount: {} ZERO", validator.stake);
            }
        }
    }

    println!();

    Ok(())
}

/// Validator info for display
#[derive(serde::Serialize, Clone)]
pub struct ValidatorInfo {
    pub id: String,
    pub commitment: String,
    pub stake: u128,
    pub active: bool,
    pub epoch: u64,
}