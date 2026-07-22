//! One-time testnet trusted setup.
//!
//! Generates the Groth16 (pk, vk) for the fixed-shape TransferCircuit and
//! computes the empty-tree Poseidon root for the 32-deep commitment tree.
//!
//! WARNING: Single-party setup (V-03). Acceptable for testnet; the toxic waste
//! is the randomness used during Groth16 circuit_specific_setup. Run this once,
//! delete the process, distribute only pk/vk. An MPC ceremony is required
//! before mainnet.
//!
//! Outputs:
//!   node/res/transfer_circuit.vk  — verifying key (committed to repo, embedded in genesis)
//!   node/res/transfer_circuit.pk  — proving key  (distribute as release artifact; gitignore)
//!
//! Prints the empty-tree Poseidon root as hex to stdout for hardcoding in genesis.

use std::path::Path;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use transfer_circuit::TransferCircuit;
use zc_crypto::poseidon::PoseidonHasher;

fn main() -> anyhow::Result<()> {
    // ── 1. Empty-tree Poseidon root ──────────────────────────────────────────
    // z[0] = [0u8;32] (empty leaf)
    // z[i] = Poseidon(z[i-1], z[i-1])
    // z[32] = root of an empty 32-deep tree
    let mut zero = [0u8; 32];
    for _ in 0..32 {
        zero = PoseidonHasher::hash_two(&zero, &zero);
    }
    println!("Empty 32-deep Poseidon Merkle root (hex, little-endian Fr):");
    println!("0x{}", hex::encode(zero));
    println!();

    // ── 2. Groth16 trusted setup ─────────────────────────────────────────────
    eprintln!("Running Groth16 circuit_specific_setup for TransferCircuit...");
    eprintln!("(This takes ~30–90 s for 87k constraints. Toxic waste is discarded on exit.)");

    let mut rng = rand::thread_rng();
    let (pk, vk) = Groth16::<ark_bn254::Bn254>::circuit_specific_setup(
        TransferCircuit::default(),
        &mut rng,
    )
    .map_err(|e| anyhow::anyhow!("Groth16 setup failed: {:?}", e))?;

    // ── 3. Serialize ─────────────────────────────────────────────────────────
    let res = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("prover parent")
        .join("node/res");
    std::fs::create_dir_all(&res)?;

    let vk_path = res.join("transfer_circuit.vk");
    let pk_path = res.join("transfer_circuit.pk");

    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes)
        .map_err(|e| anyhow::anyhow!("VK serialize: {:?}", e))?;
    std::fs::write(&vk_path, &vk_bytes)?;

    let mut pk_bytes = Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes)
        .map_err(|e| anyhow::anyhow!("PK serialize: {:?}", e))?;
    std::fs::write(&pk_path, &pk_bytes)?;

    eprintln!("VK written to {} ({} bytes)", vk_path.display(), vk_bytes.len());
    eprintln!("PK written to {} ({} bytes) — distribute as release artifact; do NOT commit", pk_path.display(), pk_bytes.len());

    // Also print the VK as hex for embedding directly if needed
    println!("VK bytes (hex) for genesis embedding:");
    println!("0x{}", hex::encode(&vk_bytes));

    Ok(())
}
