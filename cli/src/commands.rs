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
    /// Generate a new encrypted wallet keypair
    #[structopt(name = "generate-keypair")]
    GenerateKeypair(GenerateKeypairOpts),

    /// Display SR25519 account ID and ZK pubkey for an existing wallet
    #[structopt(name = "keypair")]
    Keypair(KeypairOpts),

    /// Shield transparent balance into a private note
    #[structopt(name = "shield")]
    Shield(ShieldOpts),

    /// Scan on-chain events to update note cm_index values
    #[structopt(name = "scan")]
    Scan(ScanOpts),

    /// Perform a private shielded transfer (requires a proving key)
    #[structopt(name = "transfer")]
    Transfer(TransferOpts),

    /// Submit a shielded transfer (legacy — takes a pre-built proof file)
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

    /// Rebuild the on-chain Merkle root from all stored commitments (operator sudo call)
    #[structopt(name = "update-root")]
    UpdateRoot(UpdateRootOpts),

    /// Upload a Groth16 verifying key to ProofVerifier storage via sudo
    #[structopt(name = "set-vk")]
    SetVk(SetVkOpts),

    /// Import a received note from a `transfer --export` file into the local note store
    #[structopt(name = "import-note")]
    ImportNote(ImportNoteOpts),
}

/// Options for `keypair`
#[derive(StructOpt, Debug)]
pub struct KeypairOpts {
    /// Path to the encrypted wallet keyfile
    #[structopt(short, long)]
    pub wallet: PathBuf,
}

/// Options for `shield`
#[derive(StructOpt, Debug)]
pub struct ShieldOpts {
    /// Path to the encrypted wallet keyfile (ZK identity — provides owner_pubkey for the note)
    #[structopt(short, long)]
    pub wallet: PathBuf,

    /// Amount to shield in planck (native unit)
    #[structopt(short, long)]
    pub amount: u64,

    /// Path to the note store JSON (created if absent)
    #[structopt(long, default_value = "notes.json")]
    pub note_store: PathBuf,

    /// Transaction signer: dev key (//Alice), BIP39 phrase, or 0x-prefixed 32-byte seed.
    /// This account pays transaction fees and must be funded.
    /// The ZK note owner is derived from --wallet, not from this key.
    #[structopt(long, default_value = "//Alice")]
    pub signer: String,
}

/// Options for `scan`
#[derive(StructOpt, Debug)]
pub struct ScanOpts {
    /// Path to the encrypted wallet keyfile (to match owned notes)
    #[structopt(short, long)]
    pub wallet: PathBuf,

    /// Path to the note store JSON
    #[structopt(long, default_value = "notes.json")]
    pub note_store: PathBuf,

    /// Transaction signer for the RPC connection (scan is read-only but still
    /// needs an authenticated connection on some node configs).
    #[structopt(long, default_value = "//Alice")]
    pub signer: String,
}

/// Options for `transfer`
#[derive(StructOpt, Debug)]
pub struct TransferOpts {
    /// Path to the encrypted wallet keyfile (ZK spender identity)
    #[structopt(short, long)]
    pub wallet: PathBuf,

    /// Recipient ZK pubkey (32-byte hex, Poseidon(recipient_sk))
    #[structopt(long)]
    pub to: String,

    /// Amount to transfer in planck
    #[structopt(short, long)]
    pub amount: u64,

    /// Path to the Groth16 proving key file
    #[structopt(long)]
    pub pk: PathBuf,

    /// Path to the note store JSON
    #[structopt(long, default_value = "notes.json")]
    pub note_store: PathBuf,

    /// Transaction signer: dev key (//Alice), BIP39 phrase, or 0x-prefixed seed.
    /// Must be a funded on-chain account to pay transaction fees.
    #[structopt(long, default_value = "//Alice")]
    pub signer: String,

    /// If set, write recipient note secrets to this JSON file after the proof is accepted.
    /// The recipient loads it with `import-note` to discover and later spend the received note.
    #[structopt(long)]
    pub export: Option<PathBuf>,
}

/// Options for `import-note`
#[derive(StructOpt, Debug)]
pub struct ImportNoteOpts {
    /// Recipient wallet file (must own the note — owner_pubkey verified against Poseidon(sk)).
    #[structopt(short, long)]
    pub wallet: PathBuf,

    /// JSON file produced by `transfer --export` containing the note secrets.
    #[structopt(long)]
    pub note_file: PathBuf,

    /// Recipient's note store (created if absent).
    #[structopt(long, default_value = "notes.json")]
    pub note_store: PathBuf,
}

/// Options for generate-keypair
#[derive(StructOpt, Debug)]
pub struct GenerateKeypairOpts {
    /// Output path for the encrypted keyfile
    #[structopt(short, long)]
    pub output: PathBuf,
}

/// Options for submit-shielded-transfer
#[derive(StructOpt, Debug)]
pub struct SubmitShieldedTransferOpts {
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

    /// Convert to extrinsic data.
    ///
    /// M-06: sender identity is NOT included — the extrinsic carries only the
    /// cryptographic proof, recipient commitment, and amount.  The origin is
    /// authenticated by the signed extrinsic wrapper, not by a plaintext field.
    pub fn to_extrinsic_data(&self) -> Result<Vec<u8>> {
        let proof_bytes = std::fs::read(&self.proof)?;

        // to_commitment || amount || proof  (no plaintext sender)
        let mut data = Vec::new();
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

/// Options for `update-root`
#[derive(StructOpt, Debug)]
pub struct UpdateRootOpts {
    /// Transaction signer (must be the sudo key): dev key (//Alice), BIP39 phrase, or 0x seed.
    #[structopt(long, default_value = "//Alice")]
    pub signer: String,
}

/// Options for `set-vk`
#[derive(StructOpt, Debug)]
pub struct SetVkOpts {
    /// Transaction signer (must be the sudo key): dev key (//Alice), BIP39 phrase, or 0x seed.
    #[structopt(long, default_value = "//Alice")]
    pub signer: String,

    /// Path to the serialized verifying key file (arkworks uncompressed format).
    #[structopt(long)]
    pub vk: PathBuf,
}