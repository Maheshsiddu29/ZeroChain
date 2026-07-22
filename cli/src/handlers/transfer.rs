//! Transfer commands — both the real `transfer` and the legacy `submit-shielded-transfer`.

use crate::chain::{parse_signer, ChainClient};
use crate::commands::{SubmitShieldedTransferOpts, TransferOpts};
use crate::memo::{encrypt_note_memo, IncomingViewingKey, NotePlaintext};
use crate::note_store::{bytes32_hex, hex32, NoteExport, NoteStore};
use crate::wallet::Keypair;
use anyhow::{anyhow, Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use rand::thread_rng;
use std::fs;
use transfer_circuit::{MerklePath, Note, TransferCircuit, TREE_DEPTH};
use zc_crypto::poseidon::poseidon_hash;
use zk_prover::groth16_prover;

// ============================================================================
// Real prover-based shielded transfer
// ============================================================================

pub async fn handle_transfer(opts: TransferOpts, rpc_endpoint: &str) -> Result<()> {
    // 1. Load wallet and note store
    let wallet = Keypair::from_file(&opts.wallet)?;
    let sk_fr = Fr::from_le_bytes_mod_order(&wallet.secret);
    let owner_pubkey_hex = bytes32_hex(&wallet.public);

    let mut store = NoteStore::load(&opts.note_store)?;

    // 2. Find a spendable note belonging to this wallet
    let spending_note = store
        .find_spendable(&owner_pubkey_hex)
        .ok_or_else(|| {
            anyhow!(
                "no spendable note found for owner 0x{}. \
                 Run `scan` first to update cm_index values.",
                &owner_pubkey_hex[..16]
            )
        })?
        .clone();

    if spending_note.value < opts.amount {
        anyhow::bail!(
            "note value {} is less than requested amount {}",
            spending_note.value,
            opts.amount
        );
    }

    let leaf_index = spending_note.cm_index.unwrap() as usize;
    let blinding_fr = fr_from_hex(&spending_note.blinding)?;
    let owner_pubkey_fr = poseidon_hash(&[sk_fr]);
    let asset_id_fr = fr_from_hex(&spending_note.asset_id)?;

    // 3. Parse recipient address.
    //    64-char hex → just owner_pubkey (legacy; no IVK; memos skipped for recipient).
    //    128-char hex → owner_pubkey(64) + ivk_pubkey(64) = full ZeroChain address.
    let to_clean = opts.to.strip_prefix("0x").unwrap_or(&opts.to);
    let (recipient_pk_bytes, recipient_ivk_pk): ([u8; 32], Option<[u8; 32]>) =
        if to_clean.len() == 128 {
            let owner = hex32(&to_clean[..64])
                .context("invalid --to address (owner_pubkey part)")?;
            let ivk = hex32(&to_clean[64..])
                .context("invalid --to address (ivk_pubkey part)")?;
            (owner, Some(ivk))
        } else if to_clean.len() == 64 {
            let owner = hex32(to_clean)
                .with_context(|| format!("invalid --to pubkey: {}", opts.to))?;
            (owner, None)
        } else {
            anyhow::bail!(
                "--to must be 64 hex chars (owner_pubkey) or 128 hex chars (full address); got {} chars",
                to_clean.len()
            );
        };
    let recipient_pk_fr = Fr::from_le_bytes_mod_order(&recipient_pk_bytes);

    // 4. Connect — signer pays fees; wallet provides the ZK spend key only.
    let signer_keypair = parse_signer(&opts.signer)
        .map_err(|e| anyhow!("--signer: {}", e))?;
    let client = ChainClient::connect(rpc_endpoint, signer_keypair).await?;

    let on_chain_root = client
        .get_current_merkle_root()
        .await?
        .ok_or_else(|| anyhow!("no on-chain Merkle root — operator must call update_merkle_root first"))?;

    let all_cms = client.get_all_commitments().await?;
    if leaf_index >= all_cms.len() {
        anyhow::bail!(
            "note cm_index {} out of range (chain has {} commitments)",
            leaf_index,
            all_cms.len()
        );
    }

    // 5. Build sparse Merkle path and verify root matches on-chain root
    let (computed_root, merkle_path) = compute_sparse_merkle_path(&all_cms, leaf_index);

    if computed_root != on_chain_root {
        anyhow::bail!(
            "local Merkle root (0x{}) does not match on-chain root (0x{}).\n\
             The operator must call update_merkle_root after all commitments are inserted.",
            hex::encode(computed_root),
            hex::encode(on_chain_root),
        );
    }

    // 6. Build circuit
    let input_note = Note {
        value: spending_note.value,
        asset_id: asset_id_fr,
        blinding: blinding_fr,
        owner_pubkey: owner_pubkey_fr,
    };
    let nullifier_fr = input_note.nullifier(sk_fr);
    let nullifier_bytes = fr_le_bytes(nullifier_fr);

    // Change note (if value > amount; otherwise all to recipient)
    let change_value = spending_note.value - opts.amount;
    let mut rng = thread_rng();
    let to_blinding_fr = random_fr(&mut rng);   // bound so we can export it
    let change_blinding_fr = random_fr(&mut rng);
    let output_note_to = Note {
        value: opts.amount,
        asset_id: asset_id_fr,
        blinding: to_blinding_fr,
        owner_pubkey: recipient_pk_fr,
    };
    let output_note_change = Note {
        value: change_value,
        asset_id: asset_id_fr,
        blinding: change_blinding_fr,
        owner_pubkey: owner_pubkey_fr,
    };
    let out_cm_to = output_note_to.commitment();
    let out_cm_change = output_note_change.commitment();

    let merkle_root_fr = Fr::from_le_bytes_mod_order(&on_chain_root);

    let circuit = TransferCircuit {
        input_notes: vec![input_note.clone()],
        merkle_paths: vec![merkle_path],
        output_notes: vec![output_note_to.clone(), output_note_change.clone()],
        secret_keys: vec![sk_fr],
        merkle_root: merkle_root_fr,
        nullifiers: vec![nullifier_fr],
        output_commitments: vec![out_cm_to, out_cm_change],
        asset_id: asset_id_fr,
        fee_commitment: Fr::from(0u64),
    };

    // 7. Load proving key and generate proof
    println!("Loading proving key from {}...", opts.pk.display());
    let pk = groth16_prover::load_proving_key(&opts.pk)?;

    println!("Generating Groth16 proof (this may take ~30 seconds)...");
    let proof = groth16_prover::prove(&pk, circuit)?;
    let zk_proof = groth16_prover::proof_to_zk_types(&proof)?;

    // 8. Collect public inputs
    let asset_id_bytes = fr_le_bytes(asset_id_fr);
    let out_cm_to_bytes = fr_le_bytes(out_cm_to);
    let out_cm_change_bytes = fr_le_bytes(out_cm_change);

    // 9. Build encrypted memos (one per output commitment, positionally matched).
    //    Recipient memo: encrypted to recipient IVK if full address was supplied.
    //    Change memo: encrypted to sender's own IVK so sender's scan finds it.
    let sender_ivk = IncomingViewingKey::from_spend_key(&wallet.secret);

    let to_memo: Vec<u8> = if let Some(ref ivk_pk) = recipient_ivk_pk {
        encrypt_note_memo(ivk_pk, &NotePlaintext {
            value: opts.amount,
            blinding: fr_le_bytes(to_blinding_fr),
            asset_id: asset_id_bytes,
        }, &mut rng)?
    } else {
        vec![]
    };

    let change_memo: Vec<u8> = if change_value > 0 {
        encrypt_note_memo(&sender_ivk.public, &NotePlaintext {
            value: change_value,
            blinding: fr_le_bytes(change_blinding_fr),
            asset_id: asset_id_bytes,
        }, &mut rng)?
    } else {
        vec![]
    };

    // Submit proof
    println!("Submitting proof to chain...");
    client.submit_transfer(
        &zk_proof.a,
        &zk_proof.b,
        &zk_proof.c,
        &on_chain_root,
        &[nullifier_bytes],
        &[out_cm_to_bytes, out_cm_change_bytes],
        &asset_id_bytes,
        &[0u8; 32], // fee_commitment = 0
        &[to_memo, change_memo],
    ).await?;

    // 10. Update note store
    let nullifier_hex = bytes32_hex(&nullifier_bytes);
    store.mark_spent(&nullifier_hex);

    if change_value > 0 {
        let change_note = crate::note_store::StoredNote {
            value: change_value,
            asset_id: bytes32_hex(&asset_id_bytes),
            blinding: bytes32_hex(&fr_le_bytes(change_blinding_fr)),
            owner_pubkey: owner_pubkey_hex.clone(),
            commitment: bytes32_hex(&fr_le_bytes(out_cm_change)),
            nullifier: bytes32_hex(&fr_le_bytes(output_note_change.nullifier(sk_fr))),
            cm_index: None,
            spent: false,
        };
        store.add_note(change_note);
    }
    store.save()?;

    // 11. Write recipient note export (if requested).
    if let Some(export_path) = &opts.export {
        let export = NoteExport {
            value: opts.amount,
            asset_id: bytes32_hex(&asset_id_bytes),
            blinding: bytes32_hex(&fr_le_bytes(to_blinding_fr)),
            owner_pubkey: bytes32_hex(&recipient_pk_bytes),
            commitment: bytes32_hex(&out_cm_to_bytes),
        };
        let json = serde_json::to_string_pretty(&export)?;
        std::fs::write(export_path, json)
            .with_context(|| format!("cannot write export file {}", export_path.display()))?;
        println!("  Recipient note exported to: {}", export_path.display());
    }

    println!();
    println!("Transfer complete!");
    println!("  Nullifier recorded: 0x{}", &nullifier_hex[..16]);
    println!("  To commitment:      0x{}", hex::encode(&out_cm_to_bytes[..16]));
    if change_value > 0 {
        println!("  Change ({} planck) saved to note store", change_value);
        println!("  Run `scan` to index the change note");
    }
    if recipient_ivk_pk.is_none() && opts.export.is_none() {
        println!();
        println!("Tip: pass the recipient's full 128-char address (keypair --wallet bob.key)");
        println!("     so they can discover the note via `scan --wallet bob.key`.");
        println!("     Alternatively, re-run with --export <file> for the export/import flow.");
    }

    Ok(())
}

// ============================================================================
// Legacy submit-shielded-transfer (pre-built proof file)
// ============================================================================

pub async fn handle_submit_shielded_transfer(
    opts: SubmitShieldedTransferOpts,
    _rpc_endpoint: &str,
) -> Result<()> {
    opts.validate()?;

    println!("Loading proof from {}...", opts.proof.display());
    let proof_data = fs::read(&opts.proof)?;
    println!("  Proof size: {} bytes", proof_data.len());

    // M-07: validate proof format before submission
    if proof_data.is_empty() || proof_data.len() > 4096 {
        anyhow::bail!("invalid proof size: {} bytes (expected 1–4096)", proof_data.len());
    }

    println!("Note: This legacy command does not submit the proof on-chain.");
    println!("Use `transfer` for a full end-to-end shielded transfer.");
    println!("Proof validated locally ({} bytes).", proof_data.len());

    Ok(())
}

// ============================================================================
// Sparse Merkle tree helpers
// ============================================================================

/// Compute a 32-level sparse Merkle path for leaf at `leaf_index` and return
/// (root_bytes, MerklePath).  Empty positions use the proper empty-subtree hashes:
///   z[0] = 0  (empty leaf)
///   z[k] = Poseidon(z[k-1], z[k-1])
fn compute_sparse_merkle_path(
    all_cms: &[[u8; 32]],
    leaf_index: usize,
) -> ([u8; 32], MerklePath) {
    // Precompute empty subtree roots
    let mut z = vec![Fr::from(0u64); TREE_DEPTH + 1];
    for k in 1..=TREE_DEPTH {
        z[k] = poseidon_hash(&[z[k - 1], z[k - 1]]);
    }

    // Build initial layer from on-chain commitments
    let mut layer: Vec<Fr> = all_cms
        .iter()
        .map(|c| Fr::from_le_bytes_mod_order(c))
        .collect();

    let mut siblings: Vec<Fr> = Vec::with_capacity(TREE_DEPTH);
    let mut indices: Vec<bool> = Vec::with_capacity(TREE_DEPTH);
    let mut pos = leaf_index;

    for level in 0..TREE_DEPTH {
        let sibling_pos = pos ^ 1;
        let sibling = layer.get(sibling_pos).copied().unwrap_or(z[level]);
        siblings.push(sibling);
        indices.push(pos & 1 == 1); // true if current node is a right child

        // Collapse layer to next level
        let n = (layer.len() + 1) / 2;
        let mut next = Vec::with_capacity(n);
        for i in 0..n {
            let l = layer.get(2 * i).copied().unwrap_or(z[level]);
            let r = layer.get(2 * i + 1).copied().unwrap_or(z[level]);
            next.push(poseidon_hash(&[l, r]));
        }
        layer = next;
        pos >>= 1;
    }

    let root_fr = layer.into_iter().next().unwrap_or(z[TREE_DEPTH]);
    let root_bytes = fr_le_bytes(root_fr);

    let path = MerklePath { path: siblings, indices };
    (root_bytes, path)
}

// ============================================================================
// Field element helpers
// ============================================================================

fn fr_le_bytes(fr: Fr) -> [u8; 32] {
    let le = fr.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    out
}

fn fr_from_hex(s: &str) -> Result<Fr> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("invalid hex")?;
    let mut padded = [0u8; 32];
    let n = bytes.len().min(32);
    padded[..n].copy_from_slice(&bytes[..n]);
    Ok(Fr::from_le_bytes_mod_order(&padded))
}

fn random_fr(rng: &mut impl rand::RngCore) -> Fr {
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rng.fill_bytes(&mut raw);
    Fr::from_le_bytes_mod_order(&raw)
}
