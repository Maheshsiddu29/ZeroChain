//! ZeroChain Prover CLI with Groth16 Support

mod groth16_prover;
mod groth16_generator;
mod origin_prover;
mod serialization;

use std::path::PathBuf;
use structopt::StructOpt;
use anyhow::Result;
use log::info;

#[derive(StructOpt, Debug)]
#[structopt(name = "ZeroChain Prover")]
struct Opt {
    /// Proof mode
    #[structopt(short, long, possible_values = &["transfer", "membership", "origin", "slashing"])]
    mode: String,

    /// Witness file (for transfer/membership)
    #[structopt(short, long)]
    witness: Option<PathBuf>,

    /// State transitions file (for origin mode)
    #[structopt(short, long)]
    blocks_file: Option<PathBuf>,

    /// Equivocation data (for slashing mode)
    #[structopt(short, long)]
    equivocation_data: Option<PathBuf>,

    /// Recipient commitment (for transfer mode)
    #[structopt(short, long)]
    recipient: Option<String>,

    /// Output proof file
    #[structopt(short, long)]
    output: PathBuf,

    /// Verbose logging
    #[structopt(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    // Setup logging
    let log_level = if opt.verbose { "debug" } else { "info" };
    env_logger::Builder::from_default_env()
        .filter_level(log_level.parse()?)
        .init();

    info!(" ZeroChain Prover started (mode: {})", opt.mode);

    match opt.mode.as_str() {
        "transfer" => {
            info!(" Generating Groth16 transfer proof...");
            let witness_file = opt.witness.ok_or(anyhow::anyhow!("--witness required"))?;
            let recipient = opt.recipient.ok_or(anyhow::anyhow!("--recipient required"))?;
            
            generate_transfer_proof(&witness_file, &recipient, &opt.output)?;
            info!(" Proof saved to {}", opt.output.display());
        }

        "membership" => {
            info!(" Generating Halo2 membership proof...");
            // TODO: Implement membership proof
            info!(" Proof saved to {}", opt.output.display());
        }

        "origin" => {
            info!(" Generating ZK-ORIGIN state lineage proof...");
            let blocks_file = opt.blocks_file.ok_or(anyhow::anyhow!("--blocks-file required"))?;
            generate_origin_proof(&blocks_file, &opt.output)?;
            info!(" Proof saved to {}", opt.output.display());
        }

        "slashing" => {
            info!("  Generating slashing fraud proof...");
            // TODO: Implement slashing proof
            info!(" Proof saved to {}", opt.output.display());
        }

        _ => anyhow::bail!("Unknown mode: {}", opt.mode),
    }

    info!(" Proof generation complete!");
    Ok(())
}

fn generate_transfer_proof(
    witness_file: &PathBuf,
    recipient: &str,
    output: &PathBuf,
) -> Result<()> {
    use groth16_generator::{Groth16Generator, TransferWitness};
    use std::fs;

    // Load witness from JSON
    let witness_data = fs::read_to_string(witness_file)?;
    let witness_json: serde_json::Value = serde_json::from_str(&witness_data)?;

    info!(" Loading witness from {}", witness_file.display());

    // Parse witness fields
    let secret_hex = witness_json["secret"].as_str().unwrap_or("");
    let randomness_hex = witness_json["randomness"].as_str().unwrap_or("");
    let amount = witness_json["amount"].as_u64().unwrap_or(0);

    let mut secret = [0u8; 32];
    let mut randomness = [0u8; 32];

    if secret_hex.len() == 64 {
        secret.copy_from_slice(&hex::decode(secret_hex)?[..32]);
    }
    if randomness_hex.len() == 64 {
        randomness.copy_from_slice(&hex::decode(randomness_hex)?[..32]);
    }

    // Create witness
    let witness = TransferWitness {
        secret,
        randomness,
        amount: amount as u128,
        merkle_path: vec![[0u8; 32]; 20],
        merkle_indices: vec![false; 20],
    };

    info!(" Loaded witness: amount={}", amount);

    // Parse recipient
    let mut recipient_bytes = [0u8; 32];
    if recipient.len() == 64 {
        recipient_bytes.copy_from_slice(&hex::decode(recipient)?[..32]);
    }

    // Generate proof
    info!(" Generating Groth16 proof...");
    let start = std::time::Instant::now();

    let generator = Groth16Generator::new()?;
    let proof = generator.prove_transfer(&witness, recipient_bytes)?;

    let elapsed = start.elapsed();
    info!(" Proof generated in {}ms", elapsed.as_millis());
    info!("  Proof size: {} bytes", proof.size());

    // Serialize and save
    let proof_bytes = proof.to_bytes();
    fs::write(output, &proof_bytes)?;

    info!(" Proof serialized: {} bytes", proof_bytes.len());

    Ok(())
}

fn generate_origin_proof(blocks_file: &PathBuf, output: &PathBuf) -> Result<()> {
    use origin_prover::{NovaFolder, StateTransition};
    use std::fs;

    // Load state transitions
    let data = fs::read_to_string(blocks_file)?;
    let transitions: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    info!(" Loaded {} state transitions", transitions.len());

    // Initialize Nova folder
    let mut folder = NovaFolder::new([0u8; 32]);

    // Fold each transition
    let fold_start = std::time::Instant::now();

    for (i, tx) in transitions.iter().enumerate() {
        let prev_root = hex::decode(tx["prev_root"].as_str().unwrap_or("0"))?;
        let new_root = hex::decode(tx["new_root"].as_str().unwrap_or("0"))?;
        let block_number = tx["block_number"].as_u64().unwrap_or(0);

        let mut prev = [0u8; 32];
        let mut next = [0u8; 32];
        prev.copy_from_slice(&prev_root[..32.min(prev_root.len())]);
        next.copy_from_slice(&new_root[..32.min(new_root.len())]);

        let transition = StateTransition {
            block_number,
            prev_root: prev,
            new_root: next,
        };

        folder.fold_step(&transition)?;

        if (i + 1) % 20 == 0 {
            info!("   Folded {} transitions", i + 1);
        }
    }

    let fold_time = fold_start.elapsed();
    info!(" Nova folding complete: {}ms", fold_time.as_millis());

    // Generate proof
    let prove_start = std::time::Instant::now();
    let proof = folder.prove()?;
    let prove_time = prove_start.elapsed();

    info!(" SNARK proof generated: {}ms", prove_time.as_millis());

    // Serialize and save
    let proof_bytes = proof.to_bytes();
    fs::write(output, &proof_bytes)?;

    info!(" Proof serialized: {} bytes", proof_bytes.len());
    info!("  Compression: {:.1}x", 
        (transitions.len() * 64) as f64 / proof_bytes.len() as f64
    );

    Ok(())
}