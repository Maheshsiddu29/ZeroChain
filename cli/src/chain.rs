//! Real subxt chain client — replaces mock RPC.
//!
//! Uses metadata-driven dynamic API (no generated code, no hardcoded call indices).
//! Pallet names must match the runtime: "ShieldedAssets", "ProofVerifier".
//!
//! Upgraded from subxt 0.32 to 0.44:
//!   - PairSigner (substrate-compat) removed; signing via subxt-signer sr25519::Keypair
//!   - scale-value 0.18: Value::uint() replaces Value::u128()
//!   - CheckMetadataHash handled automatically by subxt 0.44 DefaultExtrinsicParams
//!   - AuthorizeCall + WeightReclaim are zero-byte extensions; subxt 0.44 passes them
//!     through as empty bytes without failing.

use anyhow::{anyhow, Context, Result};
use subxt::{dynamic, OnlineClient, SubstrateConfig};
use subxt::ext::scale_value::Value;
use subxt_signer::{sr25519::Keypair as Sr25519Keypair, SecretUri};
use std::str::FromStr;

/// Strip the SCALE compact-integer length prefix from a `BoundedVec<u8>` blob.
/// Returns `(declared_len, body_slice)`.
fn strip_compact_prefix(raw: &[u8]) -> Result<(u64, &[u8])> {
    if raw.is_empty() {
        return Err(anyhow!("empty encoded BoundedVec"));
    }
    // Compact mode: low 2 bits encode the mode.
    let mode = raw[0] & 0b11;
    let (prefix_len, declared): (usize, u64) = match mode {
        0 => (1, (raw[0] >> 2) as u64),
        1 => {
            if raw.len() < 2 { return Err(anyhow!("truncated compact(2-byte)")); }
            let v = u16::from_le_bytes([raw[0], raw[1]]);
            (2, (v >> 2) as u64)
        }
        2 => {
            if raw.len() < 4 { return Err(anyhow!("truncated compact(4-byte)")); }
            let v = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            (4, (v >> 2) as u64)
        }
        _ => {
            // Big-integer mode: lower 6 bits = extra byte count
            let extra = (raw[0] >> 2) as usize;
            let total = 1 + extra;
            if raw.len() < total { return Err(anyhow!("truncated compact(big-int)")); }
            let mut acc = 0u64;
            for i in 0..extra {
                acc |= (raw[1 + i] as u64) << (i * 8);
            }
            (total, acc)
        }
    };
    Ok((declared, &raw[prefix_len..]))
}

/// Parse a signer key string into an sr25519 keypair.
///
/// Accepts:
/// - Dev shortcuts: `//Alice`, `//Bob`, `//Charlie`, …
/// - BIP39 mnemonic phrases
/// - Raw 32-byte seeds: `0x` + 64 hex chars
pub fn parse_signer(key: &str) -> Result<Sr25519Keypair> {
    let uri = SecretUri::from_str(key)
        .map_err(|e| anyhow!("invalid signer '{}': {}", key, e))?;
    Sr25519Keypair::from_uri(&uri)
        .map_err(|e| anyhow!("cannot build sr25519 keypair from '{}': {}", key, e))
}

pub struct ChainClient {
    inner: OnlineClient<SubstrateConfig>,
    keypair: Sr25519Keypair,
}

/// Encode a byte slice as an unnamed composite of u128 values.
/// subxt's metadata-guided encoder maps each u128 to the target scalar type (u8,
/// u32, etc.) according to the runtime type descriptor in the fetched metadata.
fn bytes_val(bytes: &[u8]) -> Value {
    Value::unnamed_composite(bytes.iter().map(|&b| Value::u128(b as u128)))
}

impl ChainClient {
    /// Connect to a running node with the given signing keypair.
    ///
    /// The signer pays transaction fees and signs extrinsics.  It is INDEPENDENT
    /// of the wallet's ZK identity: the wallet's `owner_pubkey` goes into the
    /// note commitment, while the signer account is typically a genesis-funded
    /// key such as `//Alice` on a dev chain.
    pub async fn connect(endpoint: &str, keypair: Sr25519Keypair) -> Result<Self> {
        let inner = OnlineClient::<SubstrateConfig>::from_url(endpoint)
            .await
            .with_context(|| format!("cannot connect to {}", endpoint))?;
        Ok(Self { inner, keypair })
    }

    /// Return the hex-encoded sr25519 public key of the *transaction signer*.
    /// This is the fee-paying on-chain account, NOT the ZK note owner.
    pub fn signer_account_hex(&self) -> String {
        // subxt_signer::sr25519::PublicKey(pub [u8; 32]) — .0 is the raw key bytes.
        hex::encode(self.keypair.public_key().0)
    }

    /// Submit the `shield` extrinsic and return the commitment from the Shielded event.
    /// `amount` is in planck (raw u64, the native Balance type on this chain).
    pub async fn shield(
        &self,
        amount: u64,
        owner_pubkey: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let tx = dynamic::tx(
            "ShieldedAssets",
            "shield",
            vec![
                Value::u128(amount as u128),
                bytes_val(owner_pubkey),
                bytes_val(blinding),
            ],
        );

        let in_block = self.inner.tx()
            .sign_and_submit_then_watch_default(&tx, &self.keypair)
            .await
            .context("failed to submit shield extrinsic")?
            .wait_for_finalized()
            .await
            .context("shield tx not included in finalized block")?;

        let events = in_block.fetch_events().await
            .context("failed to fetch shield events")?;

        for ev_res in events.iter() {
            let ev = ev_res.context("event decode")?;
            if ev.pallet_name() == "ShieldedAssets" && ev.variant_name() == "Shielded" {
                // Event: Shielded { commitment: Hash256, amount: BalanceOf<T> }
                // SCALE layout: [u8; 32] (32 bytes) ++ u128 (16 bytes LE)
                let raw = ev.field_bytes();
                if raw.len() >= 32 {
                    let mut cm = [0u8; 32];
                    cm.copy_from_slice(&raw[..32]);
                    return Ok(cm);
                }
            }
        }
        Err(anyhow!("shield tx included but Shielded event not emitted"))
    }

    /// Submit `submit_proof` for a ShieldedTransfer.
    ///
    /// `memos` is positionally matched with `output_commitments`: one entry per
    /// real output.  Pass an empty slice (or a slice of empty Vecs) if the
    /// caller does not have IVK pubkeys for all recipients.
    pub async fn submit_transfer(
        &self,
        proof_a: &[u8; 64],
        proof_b: &[u8; 128],
        proof_c: &[u8; 64],
        merkle_root: &[u8; 32],
        nullifiers: &[[u8; 32]],
        output_commitments: &[[u8; 32]],
        asset_id: &[u8; 32],
        fee_commitment: &[u8; 32],
        memos: &[Vec<u8>],
    ) -> Result<()> {
        let proof_value = Value::named_composite([
            ("a", bytes_val(proof_a)),
            ("b", bytes_val(proof_b)),
            ("c", bytes_val(proof_c)),
        ]);
        let inputs_value = Value::named_composite([
            ("merkle_root", bytes_val(merkle_root)),
            ("nullifiers", Value::unnamed_composite(
                nullifiers.iter().map(|n| bytes_val(n))
            )),
            ("output_commitments", Value::unnamed_composite(
                output_commitments.iter().map(|cm| bytes_val(cm))
            )),
            ("asset_id", bytes_val(asset_id)),
            ("fee_commitment", bytes_val(fee_commitment)),
        ]);
        let memos_value = Value::unnamed_composite(
            memos.iter().map(|m| {
                Value::unnamed_composite(m.iter().map(|&b| Value::u128(b as u128)))
            })
        );
        // ProofSubmission::ShieldedTransfer(Box<ShieldedTransferData>)
        // Box<T> is transparent in SCALE; encoded as one unnamed-composite field.
        let submission_value = Value::unnamed_variant("ShieldedTransfer", [
            Value::named_composite([
                ("proof", proof_value),
                ("inputs", inputs_value),
                ("memos", memos_value),
            ])
        ]);

        let tx = dynamic::tx("ProofVerifier", "submit_proof", vec![submission_value]);

        self.inner.tx()
            .sign_and_submit_then_watch_default(&tx, &self.keypair)
            .await
            .context("failed to submit transfer proof")?
            .wait_for_finalized_success()
            .await
            .context("transfer proof tx failed or not finalized")?;

        Ok(())
    }

    /// Fetch the encrypted note memo for a commitment from ProofVerifier::NoteMemos.
    /// Returns `None` if no memo is stored for this commitment.
    pub async fn get_note_memo(&self, commitment: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let key = dynamic::storage(
            "ProofVerifier",
            "NoteMemos",
            vec![bytes_val(commitment)],
        );
        let storage = self.inner.storage().at_latest().await?;
        match storage.fetch(&key).await? {
            None => Ok(None),
            Some(thunk) => {
                let raw = thunk.encoded();
                if raw.is_empty() {
                    return Ok(None);
                }
                let (_declared_len, body) = strip_compact_prefix(raw)?;
                if body.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(body.to_vec()))
                }
            }
        }
    }

    /// Return the on-chain CurrentMerkleRoot (None if not yet set).
    pub async fn get_current_merkle_root(&self) -> Result<Option<[u8; 32]>> {
        let key = dynamic::storage("ShieldedAssets", "CurrentMerkleRoot", Vec::<Value>::new());
        let storage = self.inner.storage().at_latest().await?;
        match storage.fetch(&key).await? {
            None => Ok(None),
            Some(thunk) => {
                let raw = thunk.encoded();
                if raw.len() != 32 {
                    return Err(anyhow!("unexpected CurrentMerkleRoot length: {}", raw.len()));
                }
                let mut root = [0u8; 32];
                root.copy_from_slice(raw);
                Ok(Some(root))
            }
        }
    }

    /// Return the current on-chain CommitmentCount.
    pub async fn get_commitment_count(&self) -> Result<u64> {
        let key = dynamic::storage("ShieldedAssets", "CommitmentCount", Vec::<Value>::new());
        let storage = self.inner.storage().at_latest().await?;
        match storage.fetch(&key).await? {
            None => Ok(0),
            Some(thunk) => {
                let raw = thunk.encoded();
                if raw.len() != 8 {
                    return Err(anyhow!("unexpected CommitmentCount length: {}", raw.len()));
                }
                Ok(u64::from_le_bytes(raw.try_into().unwrap()))
            }
        }
    }

    /// Fetch all on-chain commitments in order (index 0 … CommitmentCount-1).
    pub async fn get_all_commitments(&self) -> Result<Vec<[u8; 32]>> {
        let count = self.get_commitment_count().await?;
        let storage = self.inner.storage().at_latest().await?;
        let mut cms = Vec::with_capacity(count as usize);
        for i in 0..count {
            let key = dynamic::storage(
                "ShieldedAssets",
                "Commitments",
                vec![Value::u128(i as u128)],
            );
            match storage.fetch(&key).await? {
                None => break,
                Some(thunk) => {
                    let raw = thunk.encoded();
                    if raw.len() != 32 {
                        return Err(anyhow!("commitment {} has unexpected length {}", i, raw.len()));
                    }
                    let mut cm = [0u8; 32];
                    cm.copy_from_slice(raw);
                    cms.push(cm);
                }
            }
        }
        Ok(cms)
    }

    /// Submit `ProofVerifier::set_verifying_key` via sudo.
    /// `proof_type_variant` is the SCALE variant name, e.g. "Groth16Transfer".
    pub async fn set_verifying_key(&self, proof_type_variant: &str, vk_bytes: &[u8]) -> Result<()> {
        let proof_type_val = Value::unnamed_variant(proof_type_variant, vec![]);
        let key_bytes_val = Value::unnamed_composite(vk_bytes.iter().map(|&b| Value::u128(b as u128)));

        let inner_call = Value::unnamed_variant("ProofVerifier", vec![
            Value::unnamed_variant("set_verifying_key", vec![proof_type_val, key_bytes_val]),
        ]);
        let sudo_tx = dynamic::tx("Sudo", "sudo", vec![inner_call]);

        self.inner.tx()
            .sign_and_submit_then_watch_default(&sudo_tx, &self.keypair)
            .await
            .context("failed to submit sudo(set_verifying_key)")?
            .wait_for_finalized_success()
            .await
            .context("sudo(set_verifying_key) tx failed or not finalized")?;

        Ok(())
    }

    /// Return the stored byte length of a verifying key (0 if absent).
    pub async fn get_verifying_key_len(&self, proof_type_variant: &str) -> Result<u64> {
        let key = dynamic::storage(
            "ProofVerifier",
            "VerifyingKeys",
            vec![Value::unnamed_variant(proof_type_variant, vec![])],
        );
        let storage = self.inner.storage().at_latest().await?;
        match storage.fetch(&key).await? {
            None => Ok(0),
            Some(thunk) => {
                // BoundedVec<u8, _> SCALE-encodes as compact-length prefix + raw bytes.
                // We only need the byte count, so strip the compact prefix and count the rest.
                let raw = thunk.encoded();
                let (_len_prefix, body) = strip_compact_prefix(raw)?;
                Ok(body.len() as u64)
            }
        }
    }

    /// Submit `update_merkle_root` via sudo (caller must be the configured sudo key).
    pub async fn update_merkle_root(&self, root: &[u8; 32]) -> Result<()> {
        // RuntimeCall::ShieldedAssets(Call::update_merkle_root { root })
        let inner_call = Value::unnamed_variant("ShieldedAssets", vec![
            Value::unnamed_variant("update_merkle_root", vec![bytes_val(root)]),
        ]);
        let sudo_tx = dynamic::tx("Sudo", "sudo", vec![inner_call]);

        self.inner.tx()
            .sign_and_submit_then_watch_default(&sudo_tx, &self.keypair)
            .await
            .context("failed to submit sudo(update_merkle_root)")?
            .wait_for_finalized_success()
            .await
            .context("sudo(update_merkle_root) tx failed or not finalized")?;

        Ok(())
    }

    /// Subscribe to finalized blocks and call `handler(index, commitment)` for each
    /// CommitmentInserted event observed.  Blocks until the stream ends or handler returns Err.
    pub async fn subscribe_commitment_events(
        &self,
        mut handler: impl FnMut(u64, [u8; 32]) -> Result<()>,
    ) -> Result<()> {
        use futures::StreamExt;
        let mut blocks = self.inner.blocks().subscribe_finalized().await?;
        while let Some(block_res) = blocks.next().await {
            let block = block_res.context("block stream error")?;
            let events = block.events().await.context("block events error")?;
            for ev_res in events.iter() {
                let ev = ev_res.context("event decode")?;
                if ev.pallet_name() == "ShieldedAssets" && ev.variant_name() == "CommitmentInserted" {
                    // CommitmentInserted { index: u64, commitment: Hash256 }
                    // SCALE: 8 bytes (u64 LE) ++ 32 bytes ([u8; 32])
                    let raw = ev.field_bytes();
                    if raw.len() >= 40 {
                        let index = u64::from_le_bytes(raw[..8].try_into().unwrap());
                        let mut cm = [0u8; 32];
                        cm.copy_from_slice(&raw[8..40]);
                        handler(index, cm)?;
                    }
                }
            }
        }
        Ok(())
    }
}
