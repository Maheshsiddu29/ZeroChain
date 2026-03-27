//! Zero Chain Prover - Off-chain proof generation service

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use anyhow::Result;

mod groth16_prover;
mod origin_prover;
mod serialization;

use groth16_prover::*;
use origin_prover::*;

#[derive(Parser)]
#[command(name = "zero-chain-prover")]
#[command(version = "0.1.0")]
#[command(about = "Off-chain proof generation for Zero Chain", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Setup: Generate proving/verifying keys
    Setup {
        /// Output directory for keys
        #[arg(short, long, default_value = "keys/")]
        output_dir: PathBuf,
    },
    
    /// Generate a Groth16 transfer proof
    ProveTransfer {
        /// Input notes JSON file
        #[arg(short, long)]
        inputs: PathBuf,
        
        /// Output notes JSON file
        #[arg(short, long)]
        outputs: PathBuf,
        
        /// Secret key (hex)
        #[arg(short, long)]
        secret_key: String,
        
        /// Merkle root (hex)
        #[arg(short, long)]
        merkle_root: String,
        
        /// Asset ID (hex, optional)
        #[arg(short, long)]
        asset_id: Option<String>,
        
        /// Proving key path
        #[arg(short = 'k', long, default_value = "keys/transfer.pk")]
        proving_key: PathBuf,
        
        /// Output proof file
        #[arg(short = 'o', long, default_value = "proof.json")]
        output: PathBuf,
    },
    
    /// Generate ZK-ORIGIN proof
    ProveOrigin {
        /// Previous state root (hex)
        #[arg(short, long)]
        prev_state: String,
        
        /// New state root (hex)
        #[arg(short, long)]
        new_state: String,
        
        /// Block height
        #[arg(short = 't', long)]
        height: u64,
        
        /// Transactions hash (hex)
        #[arg(short = 'x', long)]
        tx_hash: String,
        
        /// Accumulator file
        #[arg(short, long, default_value = "accumulator.bin")]
        accumulator: PathBuf,
        
        /// Output proof file
        #[arg(short, long, default_value = "origin_proof.json")]
        output: PathBuf,
    },
    
    /// Verify a proof
    Verify {
        /// Proof file
        #[arg(short, long)]
        proof: PathBuf,
        
        /// Verifying key
        #[arg(short, long)]
        vk: PathBuf,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Setup { output_dir } => {
            println!(" Running trusted setup...\n");
            
            setup_keys(&output_dir)?;
            
            println!("\n Keys generated successfully!");
            println!("   Proving key: {}/transfer.pk", output_dir.display());
            println!("   Verifying key: {}/transfer.vk", output_dir.display());
            
            Ok(())
        },
        
        Commands::ProveTransfer {
            inputs,
            outputs,
            secret_key,
            merkle_root,
            asset_id,
            proving_key,
            output,
        } => {
            println!(" Generating transfer proof...\n");
            
            let proof_submission = generate_transfer_proof(
                &inputs,
                &outputs,
                &secret_key,
                &merkle_root,
                asset_id.as_deref(),
                &proving_key,
            )?;
            
            // Save to file
            let json = serde_json::to_string_pretty(&proof_submission)?;
            std::fs::write(&output, json)?;
            
            println!("\n Proof generated successfully!");
            println!("   Saved to: {}", output.display());
            
            Ok(())
        },
        
        Commands::ProveOrigin {
            prev_state,
            new_state,
            height,
            tx_hash,
            accumulator,
            output,
        } => {
            println!(" Generating ZK-ORIGIN proof...\n");
            
            let proof = generate_origin_proof(
                &prev_state,
                &new_state,
                height,
                &tx_hash,
                &accumulator,
            )?;
            
            // Save to file
            let json = serde_json::to_string_pretty(&proof)?;
            std::fs::write(&output, json)?;
            
            println!("\n Origin proof generated!");
            println!("   Saved to: {}", output.display());
            
            Ok(())
        },
        
        Commands::Verify { proof, vk } => {
            println!(" Verifying proof...\n");
            
            verify_proof(&proof, &vk)?;
            
            println!("\n Proof verification successful!");
            
            Ok(())
        },
    }
}