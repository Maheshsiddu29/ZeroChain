//! CLI command implementations

use colored::Colorize;
use std::path::PathBuf;
use anyhow::Result;

use crate::wallet::Keypair;
use crate::rpc;

/// Generate a new keypair
pub async fn cmd_keygen(output: PathBuf, verbose: bool) -> Result<()> {
    println!("{}", "Generating keypair...".cyan());

    let keypair = Keypair::generate();

    let json = serde_json::json!({
        "secret_key": hex::encode(&keypair.secret),
        "public_key": hex::encode(&keypair.public),
        "WARNING": "KEEP SECRET KEY SAFE - anyone with this can spend your notes"
    });

    let json_str = serde_json::to_string_pretty(&json)?;
    std::fs::write(&output, &json_str)?;

    println!("{} Keypair generated", "✓".green().bold());
    println!("  Public key: 0x{}", hex::encode(&keypair.public));
    println!("  Saved to: {:?}", output);

    if verbose {
        println!("  Secret key: 0x{}", hex::encode(&keypair.secret));
    }

    Ok(())
}

/// Create a witness file for shielded transfer
pub async fn cmd_create_witness(
    sender_key: PathBuf,
    amount: u64,
    recipient: String,
    output: PathBuf,
    verbose: bool,
) -> Result<()> {
    println!("{}", "Creating transfer witness...".cyan());

    // Load sender key
    let key_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&sender_key)?
    )?;

    let sender_secret = key_json["secret_key"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid key file: missing secret_key"))?;

    let recipient_hex = recipient.strip_prefix("0x").unwrap_or(&recipient);

    // Generate random blinding factors
    use zc_crypto::commitment::random_blinding;
    use zc_crypto::nullifier::random_nullifier_key;

    let blinding_input = random_blinding();
    let blinding_output = random_blinding();
    let nullifier_key = random_nullifier_key();

    let witness = serde_json::json!({
        "input_notes": [{
            "value": amount.to_string(),
            "asset_id": "0x".to_string() + &"00".repeat(32),
            "blinding": format!("0x{}", hex::encode(&blinding_input)),
            "nullifier_key": format!("0x{}", hex::encode(&nullifier_key)),
            "owner_pubkey": sender_secret,
            "merkle_path": [],
            "merkle_indices": []
        }],
        "output_notes": [{
            "value": amount.to_string(),
            "asset_id": "0x".to_string() + &"00".repeat(32),
            "blinding": format!("0x{}", hex::encode(&blinding_output)),
            "recipient_pubkey": format!("0x{}", recipient_hex)
        }]
    });

    let json = serde_json::to_string_pretty(&witness)?;
    std::fs::write(&output, &json)?;

    println!("{} Witness created", "✓".green().bold());
    println!("  Amount: {} ZERO", format_balance(amount));
    println!("  Saved to: {:?}", output);

    if verbose {
        println!("  Recipient: 0x{}", recipient_hex);
    }

    Ok(())
}

/// Check if a nullifier has been spent
pub async fn cmd_check_nullifier(
    url: &str,
    nullifier_hex: String,
    verbose: bool,
) -> Result<()> {
    let nullifier_hex = nullifier_hex.strip_prefix("0x").unwrap_or(&nullifier_hex);

    if nullifier_hex.len() != 64 {
        return Err(anyhow::anyhow!("Nullifier must be 32 bytes (64 hex characters)"));
    }

    let nullifier_bytes = hex::decode(nullifier_hex)?;

    if verbose {
        println!("Checking nullifier: 0x{}", nullifier_hex);
        println!("Connecting to: {}", url);
    }

    let is_spent = rpc::query_nullifier(url, &nullifier_bytes).await?;

    if is_spent {
        println!("{} Nullifier has been {} (note already spent)",
                 "✗".red().bold(), "spent".red());
    } else {
        println!("{} Nullifier is {} (note can still be spent)",
                 "✓".green().bold(), "unspent".green());
    }

    Ok(())
}

/// Query validator set
pub async fn cmd_query_validators(url: &str, verbose: bool) -> Result<()> {
    println!("{}", "Querying validator set...".cyan());

    if verbose {
        println!("  Connecting to: {}", url);
    }

    let info = rpc::query_validator_info(url).await?;

    println!("  Validator root: {}", info.root);
    println!("  Current epoch: {}", info.epoch);
    println!("  Active validators: {}", info.count);

    Ok(())
}

/// Check account balance
pub async fn cmd_balance(url: &str, account: String, verbose: bool) -> Result<()> {
    if verbose {
        println!("Querying balance for: {}", account);
        println!("Connecting to: {}", url);
    }

    let balance = rpc::query_balance(url, &account).await?;

    println!("{}", "Account Balance".cyan().bold());
    println!("  Address:  {}", account);
    println!("  Free:     {} ZERO", format_balance(balance.free));
    println!("  Reserved: {} ZERO", format_balance(balance.reserved));
    println!("  Total:    {} ZERO", format_balance(balance.free + balance.reserved));

    Ok(())
}

/// Show node status
pub async fn cmd_status(url: &str, _verbose: bool) -> Result<()> {
    println!("{}", "Node Status".cyan().bold());

    let status = rpc::query_node_status(url).await?;

    println!("  URL:        {}", url);
    println!("  Connected:  {}", if status.connected { "✓".green() } else { "✗".red() });
    println!("  Chain:      {}", status.chain_name);
    println!("  Block:      #{}", status.best_block);
    println!("  Finalized:  #{}", status.finalized_block);
    println!("  Peers:      {}", status.peer_count);

    Ok(())
}

fn format_balance(amount: u64) -> String {
    let whole = amount / 1_000_000_000_000;
    let frac = amount % 1_000_000_000_000;

    if frac == 0 {
        format!("{}", whole)
    } else {
        format!("{}.{:012}", whole, frac)
            .trim_end_matches('0')
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_balance() {
        assert_eq!(format_balance(1_000_000_000_000), "1");
        assert_eq!(format_balance(500_000_000_000), "0.5");
        assert_eq!(format_balance(1_500_000_000_000), "1.5");
        assert_eq!(format_balance(0), "0");
    }
}