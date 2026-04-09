//! Zero Chain CLI
//!
//! User-facing command-line tool for interacting with Zero Chain

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

mod commands;
mod rpc;
mod wallet;

use commands::*;

#[derive(Parser)]
#[command(name = "zero-chain")]
#[command(version = "0.1.0")]
#[command(about = "Zero Chain CLI - Private blockchain interactions")]
struct Cli {
    /// WebSocket URL of the Zero Chain node
    #[arg(long, default_value = "ws://127.0.0.1:9944", global = true)]
    url: String,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair
    Keygen {
        /// Output path for the keypair
        #[arg(long, default_value = "keypair.json")]
        output: PathBuf,
    },

    /// Create a witness file for a shielded transfer
    CreateWitness {
        /// Sender's secret key file
        #[arg(long)]
        sender_key: PathBuf,

        /// Amount to send
        #[arg(long)]
        amount: u64,

        /// Recipient's public key (hex)
        #[arg(long)]
        recipient: String,

        /// Output path for witness file
        #[arg(long, default_value = "witness.json")]
        output: PathBuf,
    },

    /// Check if a nullifier has been spent
    CheckNullifier {
        /// Nullifier hash in hex
        #[arg(long)]
        nullifier: String,
    },

    /// Query validator set information
    QueryValidators,

    /// Check account balance
    Balance {
        /// Account address (SS58 format)
        account: String,
    },

    /// Show node connection status
    Status,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn")
    ).init();

    let cli = Cli::parse();

    if cli.verbose {
        println!("{}", "Zero Chain CLI v0.1.0".bold().cyan());
        println!("Node URL: {}\n", cli.url);
    }

    let result = match cli.command {
        Commands::Keygen { output } => {
            cmd_keygen(output, cli.verbose).await
        }
        Commands::CreateWitness { sender_key, amount, recipient, output } => {
            cmd_create_witness(sender_key, amount, recipient, output, cli.verbose).await
        }
        Commands::CheckNullifier { nullifier } => {
            cmd_check_nullifier(&cli.url, nullifier, cli.verbose).await
        }
        Commands::QueryValidators => {
            cmd_query_validators(&cli.url, cli.verbose).await
        }
        Commands::Balance { account } => {
            cmd_balance(&cli.url, account, cli.verbose).await
        }
        Commands::Status => {
            cmd_status(&cli.url, cli.verbose).await
        }
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}