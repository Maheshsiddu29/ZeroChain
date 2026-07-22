//! ZeroChain CLI - Main entry point

mod chain;
mod commands;
mod handlers;
mod memo;
mod note_store;
mod rpc;
mod wallet;

use commands::{Cli, Command};
use handlers::*;
use structopt::StructOpt;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::from_args();
    let rpc_endpoint = cli.get_rpc_endpoint();

    match cli.command {
        Command::GenerateKeypair(opts) => handle_generate_keypair(opts)?,
        Command::Keypair(opts) => handle_keypair(opts)?,
        Command::Shield(opts) => handle_shield(opts, &rpc_endpoint).await?,
        Command::Scan(opts) => handle_scan(opts, &rpc_endpoint).await?,
        Command::Transfer(opts) => handle_transfer(opts, &rpc_endpoint).await?,
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
        Command::UpdateRoot(opts) => {
            handle_update_root(opts, &rpc_endpoint).await?
        }
        Command::SetVk(opts) => {
            handle_set_vk(opts, &rpc_endpoint).await?
        }
        Command::ImportNote(opts) => handle_import_note(opts)?,
    }

    Ok(())
}

fn handle_generate_keypair(opts: commands::GenerateKeypairOpts) -> Result<()> {
    let kp = wallet::Keypair::generate();
    let public_hex = hex::encode(kp.public);
    kp.save_to_file(&opts.output)?;
    println!("Keypair written to {}", opts.output.display());
    println!("  ZK pubkey: 0x{}", public_hex);
    Ok(())
}

async fn handle_balance(
    opts: commands::BalanceOpts,
    _rpc_endpoint: &str,
) -> Result<()> {
    let account_display = if opts.account.len() > 16 {
        format!("{}...", &opts.account[..16])
    } else {
        opts.account.clone()
    };
    println!("Account: {}", account_display);
    println!("(Balance query not yet implemented — fund this account via the faucet or transfer)");
    Ok(())
}

async fn handle_submit_slash_proof(
    opts: commands::SubmitSlashProofOpts,
    rpc_endpoint: &str,
) -> Result<()> {
    opts.validate()?;
    let client = rpc::RpcClient::new(rpc_endpoint);
    let proof_data = std::fs::read(&opts.proof)?;
    let tx_hash = client.submit_extrinsic(&proof_data).await?;
    println!("Slash proof submitted: {}", tx_hash);
    Ok(())
}
