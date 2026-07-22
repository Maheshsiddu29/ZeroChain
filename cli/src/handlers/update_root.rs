//! `update-root` command — rebuild on-chain Merkle root from all stored commitments.

use crate::chain::{parse_signer, ChainClient};
use crate::commands::UpdateRootOpts;
use anyhow::Result;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use transfer_circuit::TREE_DEPTH;
use zc_crypto::poseidon::poseidon_hash;

pub async fn handle_update_root(opts: UpdateRootOpts, rpc_endpoint: &str) -> Result<()> {
    let signer_keypair = parse_signer(&opts.signer)
        .map_err(|e| anyhow::anyhow!("--signer: {}", e))?;
    let client = ChainClient::connect(rpc_endpoint, signer_keypair).await?;

    println!("Fetching on-chain commitments...");
    let all_cms = client.get_all_commitments().await?;
    println!("  {} commitment(s) found", all_cms.len());

    println!("Computing 32-level sparse Merkle root (TREE_DEPTH=32, Poseidon BN254)...");
    let computed_root = compute_sparse_merkle_root(&all_cms);
    println!("  Computed root: 0x{}", hex::encode(computed_root));

    println!("Submitting sudo(ShieldedAssets::update_merkle_root)...");
    client.update_merkle_root(&computed_root).await?;

    println!("Verifying on-chain root...");
    let on_chain_root = client
        .get_current_merkle_root()
        .await?
        .ok_or_else(|| anyhow::anyhow!("CurrentMerkleRoot still absent after update"))?;

    if on_chain_root != computed_root {
        anyhow::bail!(
            "root mismatch: submitted 0x{} but chain reports 0x{}",
            hex::encode(computed_root),
            hex::encode(on_chain_root),
        );
    }

    println!();
    println!("Merkle root updated successfully!");
    println!("  On-chain root: 0x{}", hex::encode(on_chain_root));
    println!("  Covers {} commitment(s)", all_cms.len());

    Ok(())
}

/// Compute the 32-level sparse Merkle root using the same Poseidon empty-subtree convention
/// as the TransferCircuit: z[0] = 0, z[k] = Poseidon(z[k-1], z[k-1]).
///
/// Mirrors the logic in handlers/transfer.rs::compute_sparse_merkle_path so the operator
/// always commits the root that a spender's local path computation will agree with.
fn compute_sparse_merkle_root(all_cms: &[[u8; 32]]) -> [u8; 32] {
    // z[k] = empty-subtree root of depth k
    let mut z = vec![Fr::from(0u64); TREE_DEPTH + 1];
    for k in 1..=TREE_DEPTH {
        z[k] = poseidon_hash(&[z[k - 1], z[k - 1]]);
    }

    if all_cms.is_empty() {
        return fr_le_bytes(z[TREE_DEPTH]);
    }

    let mut layer: Vec<Fr> = all_cms
        .iter()
        .map(|c| Fr::from_le_bytes_mod_order(c))
        .collect();

    for level in 0..TREE_DEPTH {
        let n = (layer.len() + 1) / 2;
        let mut next = Vec::with_capacity(n);
        for i in 0..n {
            let l = layer.get(2 * i).copied().unwrap_or(z[level]);
            let r = layer.get(2 * i + 1).copied().unwrap_or(z[level]);
            next.push(poseidon_hash(&[l, r]));
        }
        layer = next;
    }

    fr_le_bytes(layer[0])
}

fn fr_le_bytes(fr: Fr) -> [u8; 32] {
    let le = fr.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    out
}
