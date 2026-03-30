//! Zero Chain Prover
//! 
//! Generates zero-knowledge proofs for Zero Chain transactions.
//! 
//! # Usage
//! 
//! ```bash
//! # Generate transfer proof
//! zk-prover transfer --witness witness.json --output proof.bin
//! 
//! # Setup (generate keys)
//! zk-prover setup --circuit transfer --output-dir ./keys
//! 
//! # Verify proof locally
//! zk-prover verify --proof proof.bin --vk keys/transfer.vk
//! 
//! # Generate ZK-ORIGIN proof
//! zk-prover origin --block block.json --prev genesis --output acc.bin
//! ```

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Instant;

mod groth16_prover;
mod origin_prover;
mod serialization;

use groth16_prover::TransferProver;
use origin_prover::OriginProver;

#[derive(Parser)]
#[command(name = "zk-prover")]
#[command(version = "0.1.0")]
#[command(about = "Zero Chain ZK Proof Generator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a shielded transfer proof
    Transfer {
        /// Path to witness JSON file
        #[arg(long)]
        witness: PathBuf,
        
        /// Path to proving key (optional, uses default if not specified)
        #[arg(long)]
        proving_key: Option<PathBuf>,
        
        /// Output path for the proof
        #[arg(long)]
        output: PathBuf,
        
        /// Output format: "bin" (SCALE) or "json"
        #[arg(long, default_value = "bin")]
        format: String,
    },
    
    /// Generate ZK-ORIGIN state lineage proof
    Origin {
        /// Path to block data JSON
        #[arg(long)]
        block: PathBuf,
        
        /// Previous accumulator path (or "genesis" for first block)
        #[arg(long)]
        prev: String,
        
        /// Output path for new accumulator
        #[arg(long)]
        output: PathBuf,
    },
    
    /// Run trusted setup / key generation
    Setup {
        /// Circuit type: "transfer" or "origin"
        #[arg(long)]
        circuit: String,
        
        /// Output directory for keys
        #[arg(long)]
        output_dir: PathBuf,
    },
    
    /// Verify a proof locally
    Verify {
        /// Path to proof file
        #[arg(long)]
        proof: PathBuf,
        
        /// Path to verifying key
        #[arg(long)]
        vk: PathBuf,
    },
    
    /// Export Poseidon parameters for crypto crate
    ExportPoseidon {
        /// Output path
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();
    
    let cli = Cli::parse();
    
    let result = match cli.command {
        Commands::Transfer { witness, proving_key, output, format } => {
            run_transfer(witness, proving_key, output, format)
        }
        Commands::Origin { block, prev, output } => {
            run_origin(block, prev, output)
        }
        Commands::Setup { circuit, output_dir } => {
            run_setup(circuit, output_dir)
        }
        Commands::Verify { proof, vk } => {
            run_verify(proof, vk)
        }
        Commands::ExportPoseidon { output } => {
            run_export_poseidon(output)
        }
    };
    
    if let Err(e) = result {
        log::error!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run_transfer(
    witness_path: PathBuf,
    pk_path: Option<PathBuf>,
    output_path: PathBuf,
    format: String,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("=== Shielded Transfer Proof Generation ===");
    
    // Load witness
    log::info!("Loading witness from {:?}", witness_path);
    let witness_json = std::fs::read_to_string(&witness_path)?;
    let witness: serde_json::Value = serde_json::from_str(&witness_json)?;
    
    // Load proving key
    log::info!("Loading proving key...");
    let pk = match pk_path {
        Some(path) => {
            let bytes = std::fs::read(&path)?;
            TransferProver::load_proving_key(&bytes)?
        }
        None => {
            // Try default location
            let default_path = PathBuf::from("keys/transfer.pk");
            if default_path.exists() {
                let bytes = std::fs::read(&default_path)?;
                TransferProver::load_proving_key(&bytes)?
            } else {
                return Err("No proving key found. Run 'zk-prover setup --circuit transfer' first".into());
            }
        }
    };
    
    // Generate proof
    log::info!("Generating proof...");
    let start = Instant::now();
    let (proof, public_inputs) = TransferProver::prove_from_json(&pk, &witness)?;
    let elapsed = start.elapsed();
    log::info!("Proof generated in {:?}", elapsed);
    
    // Create submission
    let submission = serialization::create_transfer_submission(
        &proof,
        public_inputs.merkle_root,
        public_inputs.nullifiers,
        public_inputs.output_commitments,
        public_inputs.asset_id,
        public_inputs.fee_commitment,
    );
    
    // Write output
    match format.as_str() {
        "bin" => {
            use codec::Encode;
            let encoded = submission.encode();
            std::fs::write(&output_path, &encoded)?;
            log::info!(" Proof written to {:?} ({} bytes)", output_path, encoded.len());
        }
        "json" => {
            let json = serde_json::to_string_pretty(&format_submission_json(&submission))?;
            std::fs::write(&output_path, &json)?;
            log::info!(" Proof written to {:?}", output_path);
        }
        _ => return Err(format!("Unknown format: {}", format).into()),
    }
    
    Ok(())
}

fn run_origin(
    block_path: PathBuf,
    prev: String,
    output_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("=== ZK-ORIGIN Proof Generation ===");
    
    // Load block data
    log::info!("Loading block data from {:?}", block_path);
    let block_json = std::fs::read_to_string(&block_path)?;
    let block: serde_json::Value = serde_json::from_str(&block_json)?;
    
    // Load previous accumulator
    let prev_acc = if prev == "genesis" {
        log::info!("Starting from genesis");
        None
    } else {
        log::info!("Loading previous accumulator from {}", prev);
        let bytes = std::fs::read(&prev)?;
        Some(OriginProver::load_accumulator(&bytes)?)
    };
    
    // Fold block
    log::info!("Folding block into accumulator...");
    let start = Instant::now();
    let new_acc = OriginProver::fold_block(prev_acc, &block)?;
    let elapsed = start.elapsed();
    log::info!("Block folded in {:?}", elapsed);
    
    // Write output
    let bytes = OriginProver::serialize_accumulator(&new_acc)?;
    std::fs::write(&output_path, &bytes)?;
    log::info!(" Accumulator written to {:?} ({} bytes)", output_path, bytes.len());
    
    Ok(())
}

fn run_setup(
    circuit: String,
    output_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(&output_dir)?;
    
    match circuit.as_str() {
        "transfer" => {
            log::info!("=== Transfer Circuit Setup ===");
            log::info!("Generating proving and verifying keys...");
            
            let start = Instant::now();
            let (pk, vk) = TransferProver::setup()?;
            let elapsed = start.elapsed();
            log::info!("Keys generated in {:?}", elapsed);
            
            // Save keys
            let pk_path = output_dir.join("transfer.pk");
            let vk_path = output_dir.join("transfer.vk");
            
            TransferProver::save_proving_key(&pk, &pk_path)?;
            TransferProver::save_verifying_key(&vk, &vk_path)?;
            
            log::info!(" Proving key saved to {:?}", pk_path);
            log::info!(" Verifying key saved to {:?}", vk_path);
        }
        "origin" => {
            log::info!("=== ZK-ORIGIN Setup ===");
            log::info!("Generating Nova public parameters...");
            
            let start = Instant::now();
            let params = OriginProver::setup()?;
            let elapsed = start.elapsed();
            log::info!("Parameters generated in {:?}", elapsed);
            
            let params_path = output_dir.join("nova_params.bin");
            OriginProver::save_params(&params, &params_path)?;
            log::info!(" Parameters saved to {:?}", params_path);
        }
        _ => {
            return Err(format!("Unknown circuit type: {}", circuit).into());
        }
    }
    
    Ok(())
}

fn run_verify(
    proof_path: PathBuf,
    vk_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("=== Local Proof Verification ===");
    
    // Load proof
    log::info!("Loading proof from {:?}", proof_path);
    let proof_bytes = std::fs::read(&proof_path)?;
    
    use codec::Decode;
    let submission = zk_types::ProofSubmission::decode(&mut &proof_bytes[..])?;
    
    // Load verifying key
    log::info!("Loading verifying key from {:?}", vk_path);
    let vk_bytes = std::fs::read(&vk_path)?;
    
    match submission {
        zk_types::ProofSubmission::ShieldedTransfer { proof, inputs } => {
            let vk = TransferProver::load_verifying_key(&vk_bytes)?;
            let is_valid = TransferProver::verify(&vk, &proof, &inputs)?;
            
            if is_valid {
                log::info!(" Proof is VALID");
            } else {
                log::error!(" Proof is INVALID");
                std::process::exit(1);
            }
        }
        _ => {
            return Err("Unsupported proof type for local verification".into());
        }
    }
    
    Ok(())
}

fn run_export_poseidon(output_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("=== Exporting Poseidon Parameters ===");
    
    use circuits_transfer::poseidon::params;
    let json = params::export_json();
    
    std::fs::write(&output_path, &json)?;
    log::info!(" Parameters exported to {:?}", output_path);
    log::info!("  Akshay: Copy these to crypto/src/poseidon.rs");
    
    Ok(())
}

fn format_submission_json(submission: &zk_types::ProofSubmission) -> serde_json::Value {
    match submission {
        zk_types::ProofSubmission::ShieldedTransfer { proof, inputs } => {
            serde_json::json!({
                "type": "ShieldedTransfer",
                "proof": {
                    "a": format!("0x{}", hex::encode(&proof.a)),
                    "b": format!("0x{}", hex::encode(&proof.b)),
                    "c": format!("0x{}", hex::encode(&proof.c)),
                },
                "inputs": {
                    "merkle_root": format!("0x{}", hex::encode(&inputs.merkle_root)),
                    "nullifiers": inputs.nullifiers.iter()
                        .map(|n| format!("0x{}", hex::encode(n)))
                        .collect::<Vec<_>>(),
                    "output_commitments": inputs.output_commitments.iter()
                        .map(|c| format!("0x{}", hex::encode(c)))
                        .collect::<Vec<_>>(),
                    "asset_id": format!("0x{}", hex::encode(&inputs.asset_id)),
                    "fee_commitment": format!("0x{}", hex::encode(&inputs.fee_commitment)),
                }
            })
        }
        _ => serde_json::json!({"error": "Unsupported proof type"})
    }
}