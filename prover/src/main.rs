//! Zero Chain ZK Prover CLI

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use anyhow::Result;

mod groth16_prover;
mod origin_prover;
mod serialization;

use groth16_prover as transfer_prover;

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
    /// Run trusted setup for a circuit
    Setup {
        #[arg(long)]
        circuit: String,
        #[arg(long, default_value = "keys")]
        output_dir: PathBuf,
    },

    /// Generate a shielded transfer proof
    Transfer {
        #[arg(long)]
        witness: PathBuf,
        #[arg(long)]
        proving_key: Option<PathBuf>,
        #[arg(long, default_value = "proof.bin")]
        output: PathBuf,
    },

    /// Verify a proof
    Verify {
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        vk: PathBuf,
        #[arg(long)]
        public_inputs: Option<PathBuf>,
    },

    /// Generate ZK-ORIGIN proof
    Origin {
        #[arg(long)]
        prev_state: String,
        #[arg(long)]
        new_state: String,
        #[arg(long)]
        height: u64,
        #[arg(long)]
        tx_hash: String,
        #[arg(long, default_value = "accumulator.bin")]
        accumulator: PathBuf,
        #[arg(long, default_value = "origin_proof.json")]
        output: PathBuf,
    },

    /// Export hash parameters
    ExportPoseidon {
        #[arg(long, default_value = "poseidon_params.json")]
        output: PathBuf,
    },
}

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Setup { circuit, output_dir } => run_setup(&circuit, &output_dir),
        Commands::Transfer { witness, proving_key, output } => run_transfer(witness, proving_key, output),
        Commands::Verify { proof, vk, public_inputs } => run_verify(proof, vk, public_inputs),
        Commands::Origin { prev_state, new_state, height, tx_hash, accumulator, output } => {
            run_origin(prev_state, new_state, height, tx_hash, accumulator, output)
        }
        Commands::ExportPoseidon { output } => run_export_poseidon(output),
    };

    if let Err(e) = result {
        log::error!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run_setup(circuit: &str, output_dir: &PathBuf) -> Result<()> {
    log::info!("Running setup for circuit: {}", circuit);
    std::fs::create_dir_all(output_dir)?;

    match circuit {
        "transfer" => {
            let (pk, vk) = transfer_prover::setup()?;

            let pk_path = output_dir.join("transfer.pk");
            let vk_path = output_dir.join("transfer.vk");

            transfer_prover::save_proving_key(&pk, &pk_path)?;
            transfer_prover::save_verifying_key(&vk, &vk_path)?;

            log::info!("Transfer circuit keys saved to {}", output_dir.display());
        }
        "origin" => {
            log::info!("Origin circuit uses Nova folding - no traditional setup needed");
            log::info!("Accumulator will be created on first proof");
        }
        _ => {
            anyhow::bail!("Unknown circuit: {}. Supported: transfer, origin", circuit);
        }
    }

    Ok(())
}

fn run_transfer(witness: PathBuf, proving_key: Option<PathBuf>, output: PathBuf) -> Result<()> {
    log::info!("Generating shielded transfer proof...");

    let witness_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&witness)?
    )?;

    let circuit = transfer_prover::build_circuit_from_witness(&witness_json)?;
    let public_inputs = transfer_prover::extract_public_inputs(&circuit);

    let pk = if let Some(pk_path) = proving_key {
        transfer_prover::load_proving_key(&pk_path)?
    } else {
        log::info!("No proving key provided, running setup and saving keys...");
        let (pk, vk) = transfer_prover::setup()?;

        let keys_dir = PathBuf::from("keys");
        std::fs::create_dir_all(&keys_dir)?;
        transfer_prover::save_proving_key(&pk, &keys_dir.join("transfer.pk"))?;
        transfer_prover::save_verifying_key(&vk, &keys_dir.join("transfer.vk"))?;
        log::info!("Keys saved to keys/ directory");

        pk
    };

    let proof = transfer_prover::prove(&pk, circuit)?;

    let submission = serialization::create_transfer_submission(&proof, &public_inputs)?;
    std::fs::write(&output, &submission)?;

    log::info!("Proof saved to {}", output.display());
    log::info!("Submission size: {} bytes", submission.len());

    Ok(())
}

fn run_verify(proof_path: PathBuf, vk_path: PathBuf, _public_inputs: Option<PathBuf>) -> Result<()> {
    log::info!("Verifying proof...");

    let vk = transfer_prover::load_verifying_key(&vk_path)?;

    let submission_bytes = std::fs::read(&proof_path)?;
    let (proof, public_inputs) = serialization::parse_transfer_submission(&submission_bytes)?;

    let valid = transfer_prover::verify(&vk, &proof, &public_inputs)?;

    if valid {
        log::info!("✓ Proof is VALID");
    } else {
        log::error!("✗ Proof is INVALID");
        std::process::exit(1);
    }

    Ok(())
}

fn run_origin(
    prev_state: String,
    new_state: String,
    height: u64,
    tx_hash: String,
    accumulator: PathBuf,
    output: PathBuf,
) -> Result<()> {
    log::info!("Generating ZK-ORIGIN proof for block {}...", height);

    let result = origin_prover::generate_origin_proof(
        &prev_state,
        &new_state,
        height,
        &tx_hash,
        &accumulator,
    )?;

    let json = serde_json::to_string_pretty(&result)?;
    std::fs::write(&output, json)?;

    log::info!("Origin proof saved to {}", output.display());

    Ok(())
}

fn run_export_poseidon(output_path: PathBuf) -> Result<()> {
    log::info!("Exporting hash parameters...");

    let params = serde_json::json!({
        "hash_type": "simplified_addition",
        "description": "Currently using simplified addition hash for development",
        "commitment": "value + asset_id + blinding + owner_pubkey",
        "nullifier": "commitment + secret_key",
        "merkle_hash": "left + right",
        "note": "Replace with Poseidon for production"
    });

    let json = serde_json::to_string_pretty(&params)?;
    std::fs::write(&output_path, json)?;

    log::info!("Parameters saved to {}", output_path.display());

    Ok(())
}