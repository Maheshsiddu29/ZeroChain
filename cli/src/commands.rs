//! CLI Commands for ZeroChain
//!
//! Provides user-facing commands for:
//! - Shielded transfers
//! - Validator registration
//! - Nullifier checking
//! - Validator set queries

use std::path::PathBuf;
use structopt::StructOpt;
use anyhow::{Result, anyhow};
use hex;

/// Main CLI structure
#[derive(StructOpt, Debug)]
#[structopt(name = "ZeroChain CLI")]
#[structopt(about = "Command-line interface for ZeroChain privacy operations")]
pub struct Cli {
    #[structopt(short, long)]
    /// RPC endpoint
    pub rpc: Option<String>,

    #[structopt(subcommand)]
    pub command: Command,
}

impl Cli {
    /// Get RPC endpoint (default or specified)
    pub fn get_rpc_endpoint(&self) -> String {
        self.rpc
            .clone()
            .unwrap_or_else(|| "http://localhost:9944".to_string())
    }
}

/// Available commands
#[derive(StructOpt, Debug)]
pub enum Command {
    /// Submit a shielded transfer
    #[structopt(name = "submit-shielded-transfer")]
    SubmitShieldedTransfer(SubmitShieldedTransferOpts),

    /// Register as a validator
    #[structopt(name = "register-validator")]
    RegisterValidator(RegisterValidatorOpts),

    /// Check if a nullifier has been used
    #[structopt(name = "check-nullifier")]
    CheckNullifier(CheckNullifierOpts),

    /// Query the current validator set
    #[structopt(name = "query-validator-set")]
    QueryValidatorSet(QueryValidatorSetOpts),

    /// Query validator details
    #[structopt(name = "query-validator")]
    QueryValidator(QueryValidatorOpts),

    /// Get account balance
    #[structopt(name = "balance")]
    Balance(BalanceOpts),

    /// Submit a slashing proof
    #[structopt(name = "submit-slash-proof")]
    SubmitSlashProof(SubmitSlashProofOpts),

    /// Generate a ZK-ORIGIN lineage proof
    #[structopt(name = "generate-lineage-proof")]
    GenerateLineageProof(GenerateLineageProofOpts),

    /// Monitor on-chain events
    #[structopt(name = "monitor")]
    Monitor(MonitorOpts),
}

/// Options for submit-shielded-transfer
#[derive(StructOpt, Debug)]
pub struct SubmitShieldedTransferOpts {
    /// Sender account
    #[structopt(short, long)]
    pub from: String,

    /// Recipient commitment (32 bytes, hex)
    #[structopt(short, long)]
    pub to_commitment: String,

    /// Amount to transfer
    #[structopt(short, long)]
    pub amount: u128,

    /// Path to proof file
    #[structopt(short, long)]
    pub proof: PathBuf,

    /// Path to witness file
    #[structopt(short, long)]
    pub witness: Option<PathBuf>,
}

impl SubmitShieldedTransferOpts {
    /// Validate options
    pub fn validate(&self) -> Result<()> {
        // Validate commitment is 32 bytes hex
        if self.to_commitment.len() != 64 {
            return Err(anyhow!("Commitment must be 64 hex characters (32 bytes)"));
        }

        hex::decode(&self.to_commitment)
            .map_err(|_| anyhow!("Commitment must be valid hex"))?;

        // Validate proof file exists
        if !self.proof.exists() {
            return Err(anyhow!("Proof file not found: {:?}", self.proof));
        }

        Ok(())
    }

    /// Convert to extrinsic data
    pub fn to_extrinsic_data(&self) -> Result<Vec<u8>> {
        // Read proof
        let proof_bytes = std::fs::read(&self.proof)?;

        // Build extrinsic: from || to_commitment || amount || proof
        let mut data = Vec::new();
        data.extend_from_slice(self.from.as_bytes());
        data.extend_from_slice(&hex::decode(&self.to_commitment)?);
        data.extend_from_slice(&self.amount.to_le_bytes());
        data.extend_from_slice(&proof_bytes);

        Ok(data)
    }
}

/// Options for register-validator
#[derive(StructOpt, Debug)]
pub struct RegisterValidatorOpts {
    /// Validator name
    #[structopt(short, long)]
    pub name: String,

    /// Commitment (32 bytes, hex)
    #[structopt(short, long)]
    pub commitment: String,

    /// Stake amount
    #[structopt(short, long)]
    pub stake: u128,

    /// Path to membership proof
    #[structopt(short, long)]
    pub proof: Option<PathBuf>,
}

impl RegisterValidatorOpts {
    pub fn validate(&self) -> Result<()> {
        if self.commitment.len() != 64 {
            return Err(anyhow!("Commitment must be 64 hex characters"));
        }

        hex::decode(&self.commitment)
            .map_err(|_| anyhow!("Commitment must be valid hex"))?;

        if self.stake == 0 {
            return Err(anyhow!("Stake must be greater than 0"));
        }

        Ok(())
    }
}

/// Options for check-nullifier
#[derive(StructOpt, Debug)]
pub struct CheckNullifierOpts {
    /// Nullifier to check (32 bytes, hex)
    #[structopt(short, long)]
    pub nullifier: String,

    /// Output format
    #[structopt(short, long, default_value = "text")]
    pub format: String,
}

impl CheckNullifierOpts {
    pub fn validate(&self) -> Result<()> {
        if self.nullifier.len() != 64 {
            return Err(anyhow!("Nullifier must be 64 hex characters"));
        }

        hex::decode(&self.nullifier)
            .map_err(|_| anyhow!("Nullifier must be valid hex"))?;

        Ok(())
    }
}

/// Options for query-validator-set
#[derive(StructOpt, Debug)]
pub struct QueryValidatorSetOpts {
    /// Output format (text, json)
    #[structopt(short, long, default_value = "text")]
    pub format: String,

    /// Show only active validators
    #[structopt(short, long)]
    pub active_only: bool,
}

/// Options for query-validator
#[derive(StructOpt, Debug)]
pub struct QueryValidatorOpts {
    /// Validator ID or commitment
    #[structopt(short, long)]
    pub id: String,

    /// Output format
    #[structopt(short, long, default_value = "text")]
    pub format: String,
}

/// Options for balance
#[derive(StructOpt, Debug)]
pub struct BalanceOpts {
    /// Account address or commitment
    #[structopt(short, long)]
    pub account: String,

    /// Output format
    #[structopt(short, long, default_value = "text")]
    pub format: String,
}

/// Options for submit-slash-proof
#[derive(StructOpt, Debug)]
pub struct SubmitSlashProofOpts {
    /// Path to fraud proof file
    #[structopt(short, long)]
    pub proof: PathBuf,

    /// Nullifier (32 bytes, hex)
    #[structopt(short, long)]
    pub nullifier: String,

    /// Block hash 1 (32 bytes, hex)
    #[structopt(short, long)]
    pub block_hash_1: String,

    /// Block hash 2 (32 bytes, hex)
    #[structopt(short, long)]
    pub block_hash_2: String,
}

impl SubmitSlashProofOpts {
    pub fn validate(&self) -> Result<()> {
        if !self.proof.exists() {
            return Err(anyhow!("Proof file not found"));
        }

        for hash in &[&self.block_hash_1, &self.block_hash_2] {
            if hash.len() != 64 {
                return Err(anyhow!("Block hash must be 64 hex characters"));
            }
            hex::decode(hash)
                .map_err(|_| anyhow!("Block hash must be valid hex"))?;
        }

        Ok(())
    }
}

/// Options for generate-lineage-proof
#[derive(StructOpt, Debug)]
pub struct GenerateLineageProofOpts {
    /// Path to state transitions file (JSON)
    #[structopt(short, long)]
    pub transitions: PathBuf,

    /// Output file for proof
    #[structopt(short, long)]
    pub output: PathBuf,

    /// Verbose output
    #[structopt(short, long)]
    pub verbose: bool,

    /// Number of parallel workers
    #[structopt(short, long, default_value = "4")]
    pub workers: usize,
}

impl GenerateLineageProofOpts {
    pub fn validate(&self) -> Result<()> {
        if !self.transitions.exists() {
            return Err(anyhow!("Transitions file not found"));
        }

        // Validate JSON format
        let content = std::fs::read_to_string(&self.transitions)?;
        serde_json::from_str::<Vec<serde_json::Value>>(&content)
            .map_err(|_| anyhow!("Invalid transitions JSON"))?;

        Ok(())
    }
}

/// Options for monitor
#[derive(StructOpt, Debug)]
pub struct MonitorOpts {
    /// Event type to monitor
    #[structopt(short, long)]
    pub event: Option<String>,

    /// Auto-refresh interval (seconds)
    #[structopt(short, long, default_value = "5")]
    pub interval: u64,

    /// Show all events
    #[structopt(short, long)]
    pub all: bool,
}