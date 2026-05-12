//! ZeroChain Prover CLI

mod groth16_prover;
mod origin_prover;
mod serialization;

use std::path::PathBuf;
use structopt::StructOpt;
use anyhow::Result;
use log::info;

// NO need to import circuits here - they're used in submodules

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

    info!("🚀 ZeroChain Prover started (mode: {})", opt.mode);

    match opt.mode.as_str() {
        "transfer" => {
            info!("📝 Generating Groth16 transfer proof...");
            let witness_file = opt.witness.ok_or(anyhow::anyhow!("--witness required for transfer mode"))?;
            groth16_prover::generate_transfer_proof(&witness_file, &opt.output)?;
            info!("✅ Proof saved to {}", opt.output.display());
        }

        "membership" => {
            info!("🌳 Generating Halo2 membership proof...");
            // TODO: Implement membership proof generation
            info!("⚠️  Membership proof generation not yet implemented");
        }

        "origin" => {
            info!("🔗 Generating ZK-ORIGIN state lineage proof...");
            let blocks_file = opt.blocks_file
                .ok_or(anyhow::anyhow!("--blocks-file required for origin mode"))?;
            generate_origin_proof(&blocks_file, &opt.output)?;
            info!("✅ Proof saved to {}", opt.output.display());
        }

        "slashing" => {
            info!("⚔️  Generating slashing fraud proof...");
            // TODO: Implement slashing proof generation
            info!("⚠️  Slashing proof generation not yet implemented");
        }

        _ => anyhow::bail!("Unknown mode: {}", opt.mode),
    }

    info!("🎉 Proof generation complete!");
    Ok(())
}

fn generate_origin_proof(blocks_file: &PathBuf, output: &PathBuf) -> Result<()> {
    use origin_prover::{OriginProver, StateTransition};
    use std::fs;

    // Load state transitions from JSON
    let data = fs::read_to_string(blocks_file)?;
    let transitions: Vec<serde_json::Value> = serde_json::from_str(&data)?;

    info!("📊 Loaded {} state transitions", transitions.len());

    // Create prover with genesis root
    let genesis = [0u8; 32]; // Replace with actual genesis from file
    let mut prover = OriginProver::new(genesis)?;

    // Fold each transition
    for (i, tx) in transitions.iter().enumerate() {
        let prev_root_hex = tx["prev_root"].as_str().unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
        let new_root_hex = tx["new_root"].as_str().unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
        let block_number = tx["block_number"].as_u64().unwrap_or(i as u64);

        // Decode hex strings
        let prev_root_vec = hex::decode(prev_root_hex)?;
        let new_root_vec = hex::decode(new_root_hex)?;

        let mut prev = [0u8; 32];
        let mut next = [0u8; 32];
        
        // Copy with bounds checking
        let prev_len = prev_root_vec.len().min(32);
        let next_len = new_root_vec.len().min(32);
        
        prev[..prev_len].copy_from_slice(&prev_root_vec[..prev_len]);
        next[..next_len].copy_from_slice(&new_root_vec[..next_len]);

        let transition = StateTransition::new(prev, next, block_number);
        prover.fold_step(transition)?;

        if (i + 1) % 10 == 0 {
            info!("  ✓ Folded {} transitions", i + 1);
        }
    }

    // Generate proof
    let proof = prover.prove()?;
    info!("✨ Proof generated: {} steps, accumulator {} bytes",
        proof.num_steps,
        proof.accumulator.len()
    );

    // Save proof
    let bytes = proof.to_bytes();
    fs::write(output, &bytes)?;
    info!("📦 Proof serialized: {} bytes", bytes.len());

    Ok(())
}