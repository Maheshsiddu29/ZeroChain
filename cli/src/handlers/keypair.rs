//! `keypair` command — display account info from a wallet file.

use crate::commands::KeypairOpts;
use crate::memo::IncomingViewingKey;
use crate::wallet::Keypair;
use anyhow::Result;

pub fn handle_keypair(opts: KeypairOpts) -> Result<()> {
    let wallet = Keypair::from_file(&opts.wallet)?;

    // SR25519 account ID (for receiving transparent tokens to shield)
    let sr25519_account_id = sr25519_account_id_hex(&wallet.secret);

    // Incoming viewing key for encrypted note-memo trial decryption
    let ivk = IncomingViewingKey::from_spend_key(&wallet.secret);
    let ivk_pubkey_hex = hex::encode(ivk.public);
    let owner_pubkey_hex = hex::encode(wallet.public);

    // Full ZeroChain address = owner_pubkey(64 hex) + ivk_pubkey(64 hex) = 128 hex chars
    let full_address = format!("{}{}", owner_pubkey_hex, ivk_pubkey_hex);

    println!("Wallet: {}", opts.wallet.display());
    println!();
    println!("SR25519 Account ID (for receiving transparent funds):");
    println!("  0x{}", sr25519_account_id);
    println!();
    println!("ZK Owner Pubkey:");
    println!("  0x{}", owner_pubkey_hex);
    println!();
    println!("Full ZeroChain Address (128 hex chars — share with senders for encrypted notes):");
    println!("  {}", full_address);
    println!();
    println!("To shield transparent tokens:");
    println!("  1. Fund the SR25519 account via faucet or transfer");
    println!("  2. Run: zerochain-cli shield --wallet <file> --amount <planck> --note-store notes.json");

    Ok(())
}

/// Derive the SR25519 account ID from the 32-byte mini-secret seed.
/// Uses subxt-signer (subxt 0.44+) — no sp-core dependency needed.
fn sr25519_account_id_hex(seed: &[u8; 32]) -> String {
    use std::str::FromStr;
    use subxt_signer::{sr25519::Keypair, SecretUri};

    let seed_hex = format!("0x{}", hex::encode(seed));
    let uri = SecretUri::from_str(&seed_hex).expect("32-byte hex is a valid SecretUri");
    let keypair = Keypair::from_uri(&uri).expect("valid mini-secret seed");
    // PublicKey(pub [u8; 32]) — .0 is the 32-byte raw key, which is the account ID.
    hex::encode(keypair.public_key().0)
}
