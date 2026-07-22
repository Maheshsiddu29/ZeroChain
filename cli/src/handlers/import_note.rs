//! `import-note` command — add a received note from a `transfer --export` file.
//!
//! The sender writes recipient note secrets to a JSON file via `transfer --export`.
//! The recipient runs this command to verify the secrets, compute the nullifier,
//! and add the note to their local store.  `scan` then assigns cm_index.

use crate::commands::ImportNoteOpts;
use crate::note_store::{bytes32_hex, hex32, NoteExport, NoteStore, StoredNote};
use crate::wallet::Keypair;
use anyhow::{Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use zc_crypto::poseidon::poseidon_hash;

pub fn handle_import_note(opts: ImportNoteOpts) -> Result<()> {
    // 1. Load wallet (recipient's ZK identity).
    let wallet = Keypair::from_file(&opts.wallet)?;
    let sk_fr = Fr::from_le_bytes_mod_order(&wallet.secret);
    let derived_pubkey_fr = poseidon_hash(&[sk_fr]);
    let derived_pubkey_bytes = fr_le_bytes(derived_pubkey_fr);

    // 2. Read and parse the export file.
    let raw = std::fs::read_to_string(&opts.note_file)
        .with_context(|| format!("cannot read note file: {}", opts.note_file.display()))?;
    let export: NoteExport = serde_json::from_str(&raw)
        .with_context(|| format!("invalid note export JSON: {}", opts.note_file.display()))?;

    // 3. Verify the note is addressed to this wallet.
    let export_pubkey = hex32(&export.owner_pubkey)
        .with_context(|| "owner_pubkey in export file is not valid 32-byte hex")?;
    if export_pubkey != derived_pubkey_bytes {
        anyhow::bail!(
            "note is not for this wallet.\n  Export owner_pubkey: 0x{}\n  This wallet pubkey:  0x{}",
            export.owner_pubkey,
            bytes32_hex(&derived_pubkey_bytes),
        );
    }

    // 4. Reconstruct note fields as field elements.
    let asset_id_bytes = hex32(&export.asset_id)
        .with_context(|| "asset_id in export is not valid 32-byte hex")?;
    let blinding_bytes = hex32(&export.blinding)
        .with_context(|| "blinding in export is not valid 32-byte hex")?;
    let export_cm_bytes = hex32(&export.commitment)
        .with_context(|| "commitment in export is not valid 32-byte hex")?;

    let owner_pk_fr = derived_pubkey_fr;
    let value_fr = Fr::from(export.value);
    let asset_id_fr = Fr::from_le_bytes_mod_order(&asset_id_bytes);
    let blinding_fr = Fr::from_le_bytes_mod_order(&blinding_bytes);

    // 5. Recompute commitment and verify it matches the export.
    //    Poseidon_t5(owner_pubkey, value, asset_id, blinding)
    let computed_cm_fr = poseidon_hash(&[owner_pk_fr, value_fr, asset_id_fr, blinding_fr]);
    let computed_cm_bytes = fr_le_bytes(computed_cm_fr);

    if computed_cm_bytes != export_cm_bytes {
        anyhow::bail!(
            "commitment verification failed — note secrets are inconsistent.\n\
             Computed:  0x{}\n  Export:    0x{}",
            bytes32_hex(&computed_cm_bytes),
            export.commitment,
        );
    }

    // 6. Compute nullifier = Poseidon(commitment, sk).
    let nullifier_fr = poseidon_hash(&[computed_cm_fr, sk_fr]);
    let nullifier_bytes = fr_le_bytes(nullifier_fr);

    // 7. Add to note store.
    let mut store = NoteStore::load(&opts.note_store)?;

    // Idempotent: skip if commitment already present.
    let cm_hex = bytes32_hex(&computed_cm_bytes);
    if store.notes.iter().any(|n| n.commitment == cm_hex) {
        println!("Note already in store (commitment 0x{}…). Nothing to do.", &cm_hex[..16]);
        return Ok(());
    }

    let note = StoredNote {
        value: export.value,
        asset_id: bytes32_hex(&asset_id_bytes),
        blinding: bytes32_hex(&blinding_bytes),
        owner_pubkey: bytes32_hex(&derived_pubkey_bytes),
        commitment: cm_hex.clone(),
        nullifier: bytes32_hex(&nullifier_bytes),
        cm_index: None,
        spent: false,
    };
    store.add_note(note);
    store.save()?;

    println!("Note imported successfully!");
    println!("  Value:      {} planck", export.value);
    println!("  Commitment: 0x{}", cm_hex);
    println!("  Note store: {}", opts.note_store.display());
    println!();
    println!("Next steps:");
    println!("  1. Run `scan --wallet <file> --note-store {}` to assign cm_index", opts.note_store.display());
    println!("  2. After the operator calls `update-root`, run `transfer` to spend this note");

    Ok(())
}

fn fr_le_bytes(fr: Fr) -> [u8; 32] {
    let le = fr.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    out
}
