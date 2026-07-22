//! `scan` command — index note cm_index values and trial-decrypt note memos.
//!
//! Phase 1 (historical) ALWAYS runs regardless of what is already in the store.
//! Two independent jobs:
//!   (a) Index-assignment: match on-chain commitments to notes already known in the store.
//!   (b) Discovery:        trial-decrypt each on-chain memo with the wallet's IVK, then
//!                         verify Poseidon(owner_pk, value, asset_id, blinding) == commitment
//!                         before adding the note to the store with its cm_index.
//!
//! Phase 2 (live subscription) only runs when there are still notes with cm_index = None
//! after Phase 1 completes.  It handles index-assignment only (the callback is synchronous
//! and cannot make async RPC calls for memo fetching — run scan again for new transfers).

use crate::chain::{parse_signer, ChainClient};
use crate::commands::ScanOpts;
use crate::memo::{IncomingViewingKey, NotePlaintext};
use crate::note_store::{bytes32_hex, NoteStore, StoredNote};
use crate::wallet::Keypair;
use anyhow::Result;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use zc_crypto::poseidon::poseidon_hash;

pub async fn handle_scan(opts: ScanOpts, rpc_endpoint: &str) -> Result<()> {
    let wallet = Keypair::from_file(&opts.wallet)?;
    let mut store = NoteStore::load(&opts.note_store)?;

    let signer_keypair = parse_signer(&opts.signer)
        .map_err(|e| anyhow::anyhow!("--signer: {}", e))?;
    let client = ChainClient::connect(rpc_endpoint, signer_keypair).await?;

    let ivk = IncomingViewingKey::from_spend_key(&wallet.secret);
    let owner_pubkey_hex = bytes32_hex(&wallet.public);
    let owner_pk_fr = Fr::from_le_bytes_mod_order(&wallet.public);
    let sk_fr = Fr::from_le_bytes_mod_order(&wallet.secret);

    // ── Phase 1: historical scan ──────────────────────────────────────────────────
    // Always iterates ALL on-chain commitments.  No early return based on store state.
    let all_cms = client.get_all_commitments().await?;
    println!("Phase 1: scanning {} on-chain commitment(s)...", all_cms.len());

    let mut indexed = 0u64;
    let mut discovered = 0u64;

    for (index, cm) in all_cms.iter().enumerate() {
        let cm_hex = bytes32_hex(cm);

        // (a) Index-assignment: if we already know this note, set its cm_index.
        if store.mark_index(&cm_hex, index as u64) {
            indexed += 1;
            println!("  [{}] indexed existing note: 0x{}...", index, &cm_hex[..16]);
        }

        // (b) Discovery via memo trial decryption.
        match client.get_note_memo(cm).await {
            Err(e) => {
                eprintln!("  [{}] memo fetch error (skipping): {}", index, e);
            }
            Ok(None) => {
                // No memo stored for this commitment — normal for shield outputs and
                // transfers that used a 64-char address (no IVK supplied).
            }
            Ok(Some(memo_bytes)) => {
                match ivk.try_decrypt(&memo_bytes) {
                    None => {
                        // Memo present but AEAD authentication failed with our IVK —
                        // belongs to a different recipient.  Silent per oracle-avoidance.
                    }
                    Some(pt) => {
                        // Verify before trusting: reconstruct commitment from plaintext
                        // and compare with what is actually on chain.
                        let expected = recompute_commitment(&owner_pk_fr, &pt);
                        if expected != *cm {
                            eprintln!(
                                "  [{}] memo decrypted but commitment mismatch — skipping (possible replay)",
                                index
                            );
                            continue;
                        }

                        if store.notes.iter().any(|n| n.commitment == cm_hex) {
                            // Note already in store (possible re-scan); ensure index is set.
                            store.mark_index(&cm_hex, index as u64);
                            continue;
                        }

                        // New note discovered!  Compute its nullifier.
                        let cm_fr = Fr::from_le_bytes_mod_order(cm);
                        let nullifier = bytes32_hex(&fr_le_bytes(poseidon_hash(&[cm_fr, sk_fr])));

                        let note = StoredNote {
                            value: pt.value,
                            asset_id: bytes32_hex(&pt.asset_id),
                            blinding: bytes32_hex(&pt.blinding),
                            owner_pubkey: owner_pubkey_hex.clone(),
                            commitment: cm_hex.clone(),
                            nullifier,
                            cm_index: Some(index as u64),
                            spent: false,
                        };
                        store.add_note(note);
                        store.save()?;
                        discovered += 1;
                        println!(
                            "  [{}] DISCOVERED: 0x{}... value={} planck",
                            index, &cm_hex[..16], pt.value
                        );
                    }
                }
            }
        }
    }

    // Persist index-assignment updates (discoveries already saved above).
    if indexed > 0 {
        store.save()?;
    }

    println!(
        "Phase 1 complete: {} indexed, {} discovered.",
        indexed, discovered
    );
    println!("Note store: {}", opts.note_store.display());

    // ── Phase 2: live subscription ────────────────────────────────────────────────
    // Only enters if there are notes still awaiting their cm_index after Phase 1.
    // Does NOT trial-decrypt (async not available in FnMut callback) — run scan
    // again after new transfers to pick up freshly stored memos.
    let unindexed_after = store
        .notes
        .iter()
        .filter(|n| n.cm_index.is_none() && !n.spent)
        .count();

    if unindexed_after == 0 {
        return Ok(());
    }

    println!(
        "Phase 2: {} note(s) still unindexed — watching live events (Ctrl+C to stop)...",
        unindexed_after
    );

    let note_store_path = opts.note_store.clone();

    let result = client
        .subscribe_commitment_events(|index, cm| {
            let cm_hex = bytes32_hex(&cm);
            if store.mark_index(&cm_hex, index) {
                println!("  [{}] indexed: 0x{}...", index, &cm_hex[..16]);
                store.save()?;
                let left = store
                    .notes
                    .iter()
                    .filter(|n| n.cm_index.is_none() && !n.spent)
                    .count();
                if left == 0 {
                    println!("All notes indexed. Scan complete.");
                }
            }
            Ok(())
        })
        .await;

    // Persist even on Ctrl+C / stream drop.
    let _ = store.save();

    if let Err(e) = result {
        eprintln!("Scan ended: {}", e);
    }

    println!("Note store updated: {}", note_store_path.display());
    Ok(())
}

/// Recompute the note commitment from decrypted plaintext + wallet's owner pubkey.
/// Used to verify the memo is authentic before trusting the plaintext.
fn recompute_commitment(owner_pk_fr: &Fr, pt: &NotePlaintext) -> [u8; 32] {
    let value_fr = Fr::from(pt.value);
    let asset_id_fr = Fr::from_le_bytes_mod_order(&pt.asset_id);
    let blinding_fr = Fr::from_le_bytes_mod_order(&pt.blinding);
    fr_le_bytes(poseidon_hash(&[*owner_pk_fr, value_fr, asset_id_fr, blinding_fr]))
}

fn fr_le_bytes(fr: Fr) -> [u8; 32] {
    let le = fr.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    out
}
