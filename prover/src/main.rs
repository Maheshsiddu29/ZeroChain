//! Zero Chain Prover Binary
//! 
//! Generates ZK proofs off-chain and outputs them in the format
//! expected by pallet-proof-verifier

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod groth16_prover;
mod serialization;

use groth16_prover::*;
use serialization::*;

#[derive(Parser)]
#[command(name = "zero-chain-prover")]
#[command(about = "Off-chain proof generation service for Zero Chain")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a Groth16 transfer proof
    ProveTransfer {
        /// Input notes JSON file
        #[arg(short, long)]
        inputs: PathBuf,
        
        /// Output notes JSON file
        #[arg(short, long)]
        outputs: PathBuf,
        
        /// Secret key (hex-encoded)
        #[arg(short, long)]
        secret_key: String,
        
        /// Proving key path
        #[arg(short, long, default_value = "keys/transfer.pk")]
        proving_key: PathBuf,
        
        /// Output proof JSON
        #[arg(short = 'o', long, default_value = "proof.json")]
        output: PathBuf,
    },
    
    /// Setup: generate proving/verifying keys
    Setup {
        /// Output directory for keys
        #[arg(short, long, default_value = "keys/")]
        output_dir: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::ProveTransfer { inputs, outputs, secret_key, proving_key, output } => {
            println!(" Generating transfer proof...");
            
            // Load inputs
            let input_notes = load_notes(&inputs)?;
            let output_notes = load_notes(&outputs)?;
            let sk = hex_to_field_element(&secret_key)?;
            
            // Load proving key
            let pk = load_proving_key(&proving_key)?;
            
            // Generate proof
            let (proof, public_inputs) = prove_transfer(
                &input_notes,
                &output_notes,
                &sk,
                &pk,
            )?;
            
            // Serialize to primitives/zk-types format
            let proof_submission = serialize_transfer_proof(proof, public_inputs)?;
            
            // Save to JSON
            save_proof_submission(&output, &proof_submission)?;
            
            println!(" Proof generated and saved to: {}", output.display());
            println!("   Submit to chain with: zero-chain-cli submit-transfer {}", output.display());
            
            Ok(())
        },
        
        Commands::Setup { output_dir } => {
            println!(" Running trusted setup...");
            
            setup_groth16_keys(&output_dir)?;
            
            println!(" Keys generated:");
            println!("   Proving key: {}/transfer.pk", output_dir.display());
            println!("   Verifying key: {}/transfer.vk", output_dir.display());
            
            Ok(())
        },
    }
}