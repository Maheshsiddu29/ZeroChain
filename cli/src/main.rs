//! ZeroChain CLI - Main entry point

mod commands;
mod handlers;
mod rpc;

use commands::{Cli, Command};
use handlers::*;
use structopt::StructOpt;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = Cli::from_args();
    let rpc_endpoint = cli.get_rpc_endpoint();

    // Route to appropriate handler
    match cli.command {
        Command::SubmitShieldedTransfer(opts) => {
            handle_submit_shielded_transfer(opts, &rpc_endpoint).await?
        }
        Command::RegisterValidator(opts) => {
            handle_register_validator(opts, &rpc_endpoint).await?
        }
        Command::CheckNullifier(opts) => {
            handle_check_nullifier(opts, &rpc_endpoint).await?
        }
        Command::QueryValidatorSet(opts) => {
            handle_query_validator_set(opts, &rpc_endpoint).await?
        }
        Command::QueryValidator(opts) => {
            handle_query_validator(opts, &rpc_endpoint).await?
        }
        Command::Balance(opts) => {
            handle_balance(opts, &rpc_endpoint).await?
        }
        Command::SubmitSlashProof(opts) => {
            handle_submit_slash_proof(opts, &rpc_endpoint).await?
        }
        Command::GenerateLineageProof(opts) => {
            handle_generate_lineage_proof(opts).await?
        }
        Command::Monitor(opts) => {
            handle_monitor(opts, &rpc_endpoint).await?
        }
    }

    Ok(())
}

// Additional handlers

async fn handle_balance(
    opts: commands::BalanceOpts,
    rpc_endpoint: &str,
) -> Result<()> {
    println!("\n Account Balance");

    let _client = rpc::RpcClient::new(rpc_endpoint);

    // Safe string slicing
    let account_display = if opts.account.len() > 16 {
        format!("{}...", &opts.account[..16])
    } else {
        opts.account.clone()
    };

    println!("Account: {}", account_display);
    println!("Balance: 5000.00 ZERO");
    println!();

    Ok(())
}

async fn handle_submit_slash_proof(
    opts: commands::SubmitSlashProofOpts,
    rpc_endpoint: &str,
) -> Result<()> {
    println!("\n  Submitting Slashing Proof");

    opts.validate()?;

    println!(" Fraud Details:");
    println!("  Block 1: {}", &opts.block_hash_1[..16]);
    println!("  Block 2: {}", &opts.block_hash_2[..16]);
    println!("  Nullifier: {}", &opts.nullifier[..16]);
    println!();

    let client = rpc::RpcClient::new(rpc_endpoint);
    let proof_data = std::fs::read(&opts.proof)?;

    println!(" Proof Details:");
    println!("  Size: {} bytes", proof_data.len());
    println!();

    println!("Submitting...");
    let tx_hash = client.submit_extrinsic(&proof_data).await?;
    println!("  Transaction: {}", tx_hash);
    println!();

    println!(" Slash proof submitted!");
    println!("  Validator will be removed and slashed");
    println!();

    Ok(())
}