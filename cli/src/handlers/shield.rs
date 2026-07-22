//! `shield` command — convert transparent balance to a private note.

use crate::chain::{parse_signer, ChainClient};
use crate::commands::ShieldOpts;
use crate::note_store::{bytes32_hex, NoteStore, StoredNote};
use crate::wallet::Keypair;
use anyhow::Result;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use rand::RngCore;
use zc_crypto::poseidon::poseidon_hash;

pub async fn handle_shield(opts: ShieldOpts, rpc_endpoint: &str) -> Result<()> {
    if opts.amount == 0 {
        anyhow::bail!("shield amount must be > 0");
    }

    let wallet = Keypair::from_file(&opts.wallet)?;

    // ZK spend key and owner pubkey
    let sk_fr = Fr::from_le_bytes_mod_order(&wallet.secret);
    let owner_pubkey_fr = poseidon_hash(&[sk_fr]);
    let owner_pubkey_bytes = fr_le_bytes(owner_pubkey_fr);
    // Sanity-check: must match wallet.public
    debug_assert_eq!(owner_pubkey_bytes, wallet.public);

    // Random blinding factor
    let mut rng = rand::thread_rng();
    let mut blinding_raw = [0u8; 32];
    rng.fill_bytes(&mut blinding_raw);
    // Reduce mod Fr order so it's a valid field element
    let blinding_fr = Fr::from_le_bytes_mod_order(&blinding_raw);
    let blinding_bytes = fr_le_bytes(blinding_fr);

    // Compute expected commitment (Poseidon_t5)
    let value_fr = Fr::from(opts.amount);
    let asset_id_fr = Fr::from(0u64); // native asset
    let cm_fr = poseidon_hash(&[owner_pubkey_fr, value_fr, asset_id_fr, blinding_fr]);
    let cm_bytes = fr_le_bytes(cm_fr);

    // Compute nullifier so we can store it
    let nullifier_fr = poseidon_hash(&[cm_fr, sk_fr]);
    let nullifier_bytes = fr_le_bytes(nullifier_fr);

    // Transaction signer: pays fees, must be funded (separate from ZK identity).
    let signer_keypair = parse_signer(&opts.signer)
        .map_err(|e| anyhow::anyhow!("--signer: {}", e))?;
    let signer_hex = hex::encode(signer_keypair.public_key().0);

    println!("Shielding {} planck...", opts.amount);
    println!("  Transaction signer (fee payer): 0x{}", signer_hex);
    println!("  ZK owner pubkey (note owner):   0x{}", hex::encode(owner_pubkey_bytes));
    println!("  Expected commitment:             0x{}", hex::encode(cm_bytes));

    let client = ChainClient::connect(rpc_endpoint, signer_keypair).await?;

    let on_chain_cm = client.shield(opts.amount, &owner_pubkey_bytes, &blinding_bytes).await?;

    if on_chain_cm != cm_bytes {
        anyhow::bail!(
            "commitment mismatch: expected 0x{} but chain emitted 0x{}",
            hex::encode(cm_bytes),
            hex::encode(on_chain_cm),
        );
    }

    // Persist note secrets
    let note = StoredNote {
        value: opts.amount,
        asset_id: bytes32_hex(&fr_le_bytes(asset_id_fr)),
        blinding: bytes32_hex(&blinding_bytes),
        owner_pubkey: bytes32_hex(&owner_pubkey_bytes),
        commitment: bytes32_hex(&cm_bytes),
        nullifier: bytes32_hex(&nullifier_bytes),
        cm_index: None, // populated by `scan`
        spent: false,
    };
    let mut store = NoteStore::load(&opts.note_store)?;
    store.add_note(note);
    store.save()?;

    println!();
    println!("Shield successful!");
    println!("  Commitment: 0x{}", hex::encode(cm_bytes));
    println!("  Note saved to: {}", opts.note_store.display());
    println!();
    println!("IMPORTANT: The note is NOT yet spendable.");
    println!("  The node operator must call update_merkle_root to include");
    println!("  this commitment in the on-chain Merkle tree before you can");
    println!("  generate a valid transfer proof.");
    println!();
    println!("Next steps:");
    println!("  1. Run `scan` to confirm the note is indexed on-chain");
    println!("  2. Wait for the operator to call update_merkle_root");
    println!("  3. Run `transfer` to spend the note privately");

    Ok(())
}

/// Convert Fr to 32-byte little-endian representation.
fn fr_le_bytes(fr: Fr) -> [u8; 32] {
    use ark_ff::BigInteger;
    let le = fr.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    out
}
