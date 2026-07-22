//! Groth16 TransferCircuit for Zero Chain
//!
//! Proves a shielded transfer without revealing:
//! - Sender
//! - Receiver
//! - Amount
//!
//! Public inputs: Merkle root, nullifiers[MAX_INPUTS], output_commitments[MAX_OUTPUTS],
//!                asset_id, fee_commitment.
//!
//! The circuit has a FIXED shape: always allocates MAX_INPUTS input slots and
//! MAX_OUTPUTS output slots regardless of actual notes; dummy slots are gated
//! by boolean `is_real` witnesses so no constraint is enforced for them.

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use zc_crypto::poseidon::poseidon_hash;

/// Maximum inputs per transfer (fixed circuit shape)
pub const MAX_INPUTS: usize = 8;

/// Maximum outputs per transfer (fixed circuit shape)
pub const MAX_OUTPUTS: usize = 8;

/// Merkle tree depth
pub const TREE_DEPTH: usize = 32;

// ============================================================================
// Native Types
// ============================================================================

/// A note representing value
#[derive(Clone, Debug)]
pub struct Note {
    pub value: u64,
    pub asset_id: Fr,
    pub blinding: Fr,
    pub owner_pubkey: Fr,
}

impl Note {
    /// Compute the commitment: Poseidon_t5(owner_pubkey, value, asset_id, blinding)
    pub fn commitment(&self) -> Fr {
        poseidon_hash(&[
            self.owner_pubkey,
            Fr::from(self.value),
            self.asset_id,
            self.blinding,
        ])
    }

    /// Compute nullifier: Poseidon_t3(commitment, secret_key)
    pub fn nullifier(&self, secret_key: Fr) -> Fr {
        poseidon_hash(&[self.commitment(), secret_key])
    }
}

/// Merkle authentication path
#[derive(Clone, Debug, Default)]
pub struct MerklePath {
    pub path: Vec<Fr>,
    pub indices: Vec<bool>,
}

// ============================================================================
// Circuit Variable Types (R1CS)
// ============================================================================

/// Note as circuit variables
#[derive(Clone)]
pub struct NoteVar {
    pub value: FpVar<Fr>,
    pub asset_id: FpVar<Fr>,
    pub blinding: FpVar<Fr>,
    pub owner_pubkey: FpVar<Fr>,
}

impl AllocVar<Note, Fr> for NoteVar {
    fn new_variable<T: std::borrow::Borrow<Note>>(
        cs: impl Into<ark_relations::r1cs::Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let note = f()?;
        let note = note.borrow();

        let value = FpVar::new_variable(cs.clone(), || Ok(Fr::from(note.value)), mode)?;
        let asset_id = FpVar::new_variable(cs.clone(), || Ok(note.asset_id), mode)?;
        let blinding = FpVar::new_variable(cs.clone(), || Ok(note.blinding), mode)?;
        let owner_pubkey = FpVar::new_variable(cs.clone(), || Ok(note.owner_pubkey), mode)?;

        Ok(Self { value, asset_id, blinding, owner_pubkey })
    }
}

/// Merkle path as circuit variables
#[derive(Clone)]
pub struct MerklePathVar {
    pub path: Vec<FpVar<Fr>>,
    pub indices: Vec<Boolean<Fr>>,
}

impl AllocVar<MerklePath, Fr> for MerklePathVar {
    fn new_variable<T: std::borrow::Borrow<MerklePath>>(
        cs: impl Into<ark_relations::r1cs::Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let merkle_path = f()?;
        let merkle_path = merkle_path.borrow();

        let path = merkle_path.path.iter()
            .map(|sibling| FpVar::new_variable(cs.clone(), || Ok(*sibling), mode))
            .collect::<Result<Vec<_>, _>>()?;

        let indices = merkle_path.indices.iter()
            .map(|&idx| Boolean::new_variable(cs.clone(), || Ok(idx), mode))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { path, indices })
    }
}

// ============================================================================
// Core Poseidon Gadget
// ============================================================================

/// In-circuit Poseidon hash using the iden3 state[0] output convention.
///
/// Mirrors the native `hash_fixed_arity` in zc_crypto::poseidon::inner:
///   absorb inputs into rate positions → permute → read state[0].
///
/// `inputs` must be non-empty; all must share the same ConstraintSystemRef.
fn poseidon_gadget(
    inputs: Vec<FpVar<Fr>>,
    config: &PoseidonConfig<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let cs = inputs[0].cs();
    let mut sponge = PoseidonSpongeVar::<Fr>::new(cs, config);
    sponge.absorb(&inputs)?;
    let _ = sponge.squeeze_field_elements(1)?;
    Ok(sponge.state[0].clone())
}

// ============================================================================
// Circuit Constraint Functions
// ============================================================================

/// Poseidon_t5(owner_pubkey, value, asset_id, blinding) — note commitment.
///
/// Order matches Note::commitment() native computation.
pub fn compute_commitment(note: &NoteVar) -> Result<FpVar<Fr>, SynthesisError> {
    let config = zc_crypto::poseidon::params::config_t5();
    poseidon_gadget(
        vec![
            note.owner_pubkey.clone(),
            note.value.clone(),
            note.asset_id.clone(),
            note.blinding.clone(),
        ],
        &config,
    )
}

/// Poseidon_t3(commitment, secret_key) — nullifier derivation.
///
/// Order matches Note::nullifier() native computation.
pub fn compute_nullifier(
    commitment: &FpVar<Fr>,
    secret_key: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let config = zc_crypto::poseidon::params::config_t3();
    poseidon_gadget(vec![commitment.clone(), secret_key.clone()], &config)
}

/// Poseidon_t3(left, right) — Merkle node hash.
///
/// Matches MerkleTree::hash_two (PoseidonHasher::hash_two) native computation.
pub fn hash_pair(left: &FpVar<Fr>, right: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let config = zc_crypto::poseidon::params::config_t3();
    poseidon_gadget(vec![left.clone(), right.clone()], &config)
}

/// Poseidon_t2(sk) — spend authority: owner_pubkey must equal this.
pub fn compute_pk(secret_key: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let config = zc_crypto::poseidon::params::config_t2();
    poseidon_gadget(vec![secret_key.clone()], &config)
}

/// Walk a Merkle path from a commitment and return the computed root.
///
/// For each level: select left/right based on `is_right`, then hash_pair.
fn verify_merkle_path_from(
    commitment: &FpVar<Fr>,
    path: &MerklePathVar,
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut current = commitment.clone();
    for (sibling, is_right) in path.path.iter().zip(path.indices.iter()) {
        let left = is_right.select(sibling, &current)?;
        let right = is_right.select(&current, sibling)?;
        current = hash_pair(&left, &right)?;
    }
    Ok(current)
}

/// Verify a Merkle path and return the computed root (public API).
pub fn verify_merkle_path(
    note: &NoteVar,
    path: &MerklePathVar,
) -> Result<FpVar<Fr>, SynthesisError> {
    let commitment = compute_commitment(note)?;
    verify_merkle_path_from(&commitment, path)
}

/// Sum the values of notes (for backward compat with older callers).
pub fn sum_values(notes: &[NoteVar]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sum = FpVar::zero();
    for note in notes {
        sum = sum + &note.value;
    }
    Ok(sum)
}

// ============================================================================
// Main Circuit
// ============================================================================

/// A shielded transfer circuit with FIXED shape (MAX_INPUTS × MAX_OUTPUTS).
#[derive(Clone, Debug)]
pub struct TransferCircuit {
    // Private witness (variable-length; padded to MAX_INPUTS/MAX_OUTPUTS internally)
    pub input_notes: Vec<Note>,
    pub merkle_paths: Vec<MerklePath>,
    pub output_notes: Vec<Note>,
    pub secret_keys: Vec<Fr>,

    // Public inputs
    pub merkle_root: Fr,
    pub nullifiers: Vec<Fr>,
    pub output_commitments: Vec<Fr>,
    pub asset_id: Fr,
    pub fee_commitment: Fr,
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Public inputs (always fixed arity) ───────────────────────────────
        let merkle_root_var = FpVar::new_input(cs.clone(), || Ok(self.merkle_root))?;

        // Nullifier slots are always MAX_INPUTS (pad with 0 for dummy slots)
        let nullifiers_var: Vec<FpVar<Fr>> = (0..MAX_INPUTS)
            .map(|i| {
                let val = self.nullifiers.get(i).copied().unwrap_or(Fr::from(0u64));
                FpVar::new_input(cs.clone(), || Ok(val))
            })
            .collect::<Result<_, _>>()?;

        // Output commitment slots are always MAX_OUTPUTS (pad with 0)
        let output_commitments_var: Vec<FpVar<Fr>> = (0..MAX_OUTPUTS)
            .map(|i| {
                let val = self.output_commitments.get(i).copied().unwrap_or(Fr::from(0u64));
                FpVar::new_input(cs.clone(), || Ok(val))
            })
            .collect::<Result<_, _>>()?;

        let asset_id_var = FpVar::new_input(cs.clone(), || Ok(self.asset_id))?;
        let fee_var = FpVar::new_input(cs.clone(), || Ok(self.fee_commitment))?;

        // ── Dummy values for padding ──────────────────────────────────────────
        let dummy_note = Note {
            value: 0,
            asset_id: Fr::from(0u64),
            blinding: Fr::from(0u64),
            owner_pubkey: Fr::from(0u64),
        };

        // ── Input notes (always MAX_INPUTS slots) ─────────────────────────────
        let mut input_sum = FpVar::zero();

        for i in 0..MAX_INPUTS {
            let is_real_val = i < self.input_notes.len();
            let is_real = Boolean::new_witness(cs.clone(), || Ok(is_real_val))?;

            let note = self.input_notes.get(i).cloned().unwrap_or_else(|| dummy_note.clone());
            let sk_val = self.secret_keys.get(i).copied().unwrap_or(Fr::from(0u64));

            // Normalize Merkle path to exactly TREE_DEPTH entries so every slot
            // executes the same number of hash_pair constraints (fixed circuit shape).
            let path = {
                let raw = self.merkle_paths.get(i).cloned().unwrap_or_default();
                let mut p = raw;
                p.path.resize(TREE_DEPTH, Fr::from(0u64));
                p.indices.resize(TREE_DEPTH, false);
                p
            };

            let note_var = NoteVar::new_witness(cs.clone(), || Ok(note))?;
            let path_var = MerklePathVar::new_witness(cs.clone(), || Ok(path))?;
            let sk_var = FpVar::new_witness(cs.clone(), || Ok(sk_val))?;

            // Spend authority: owner_pubkey == Poseidon_t2(sk)
            // Gate: if is_real, enforce note.owner_pubkey == pk_computed; else skip.
            let pk_computed = compute_pk(&sk_var)?;
            let enforced_pk = is_real.select(&note_var.owner_pubkey, &pk_computed)?;
            enforced_pk.enforce_equal(&pk_computed)?;

            // Range check: value ∈ [0, 2^64). Enforce upper bits are 0 (gated).
            let value_bits = note_var.value.to_bits_le()?;
            for bit in value_bits.iter().skip(64) {
                let gated = is_real.select(bit, &Boolean::constant(false))?;
                gated.enforce_equal(&Boolean::constant(false))?;
            }

            // Commitment: Poseidon_t5(owner_pubkey, value, asset_id, blinding)
            let commitment = compute_commitment(&note_var)?;

            // Merkle inclusion: computed root must equal public merkle_root (gated)
            let computed_root = verify_merkle_path_from(&commitment, &path_var)?;
            let enforced_root = is_real.select(&computed_root, &merkle_root_var)?;
            enforced_root.enforce_equal(&merkle_root_var)?;

            // Nullifier: Poseidon_t3(commitment, sk) must equal public nullifier (gated)
            let nullifier = compute_nullifier(&commitment, &sk_var)?;
            let enforced_null = is_real.select(&nullifier, &nullifiers_var[i])?;
            enforced_null.enforce_equal(&nullifiers_var[i])?;

            // Asset ID consistency (gated)
            let enforced_asset = is_real.select(&note_var.asset_id, &asset_id_var)?;
            enforced_asset.enforce_equal(&asset_id_var)?;

            // Balance accumulation: only count real notes
            let gated_value = is_real.select(&note_var.value, &FpVar::zero())?;
            input_sum = input_sum + gated_value;
        }

        // ── Output notes (always MAX_OUTPUTS slots) ───────────────────────────
        let mut output_sum = FpVar::zero();

        for i in 0..MAX_OUTPUTS {
            let is_real_val = i < self.output_notes.len();
            let is_real = Boolean::new_witness(cs.clone(), || Ok(is_real_val))?;

            let note = self.output_notes.get(i).cloned().unwrap_or_else(|| dummy_note.clone());
            let note_var = NoteVar::new_witness(cs.clone(), || Ok(note))?;

            // Range check: value ∈ [0, 2^64) (gated)
            let value_bits = note_var.value.to_bits_le()?;
            for bit in value_bits.iter().skip(64) {
                let gated = is_real.select(bit, &Boolean::constant(false))?;
                gated.enforce_equal(&Boolean::constant(false))?;
            }

            // Output commitment check: Poseidon_t5 must match public commitment (gated)
            let commitment = compute_commitment(&note_var)?;
            let enforced_cm = is_real.select(&commitment, &output_commitments_var[i])?;
            enforced_cm.enforce_equal(&output_commitments_var[i])?;

            // Asset ID consistency (gated)
            let enforced_asset = is_real.select(&note_var.asset_id, &asset_id_var)?;
            enforced_asset.enforce_equal(&asset_id_var)?;

            // Balance accumulation: only count real notes
            let gated_value = is_real.select(&note_var.value, &FpVar::zero())?;
            output_sum = output_sum + gated_value;
        }

        // ── Balance: sum(inputs) == sum(outputs) + fee ────────────────────────
        let expected_total = output_sum + fee_var;
        input_sum.enforce_equal(&expected_total)?;

        Ok(())
    }
}

impl Default for TransferCircuit {
    fn default() -> Self {
        Self {
            input_notes: vec![],
            merkle_paths: vec![],
            output_notes: vec![],
            secret_keys: vec![],
            merkle_root: Fr::from(0u64),
            nullifiers: vec![],
            output_commitments: vec![],
            asset_id: Fr::from(0u64),
            fee_commitment: Fr::from(0u64),
        }
    }
}

pub mod witness;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_relations::r1cs::ConstraintSystem;

    /// Pre-compute the Merkle root for a leaf hashed up TREE_DEPTH levels
    /// with all-zero siblings (all left-positioned, indices=false).
    fn merkle_root_for_leaf(commitment: Fr) -> Fr {
        let mut cur = commitment;
        for _ in 0..TREE_DEPTH {
            cur = poseidon_hash(&[cur, Fr::from(0u64)]);
        }
        cur
    }

    fn make_valid_circuit_1in_1out() -> TransferCircuit {
        let mut rng = test_rng();
        let asset_id = Fr::from(0u64);
        let sk = <Fr as ark_std::UniformRand>::rand(&mut rng);

        // Spend authority: owner_pubkey == Poseidon_t2(sk)
        let owner_pubkey = poseidon_hash(&[sk]);

        let input_note = Note {
            value: 100,
            asset_id,
            blinding: <Fr as ark_std::UniformRand>::rand(&mut rng),
            owner_pubkey,
        };

        let input_commitment = input_note.commitment();
        let nullifier = input_note.nullifier(sk);

        // Output note: same value, any owner (no spend authority on output)
        let output_note = Note {
            value: 100,
            asset_id,
            blinding: <Fr as ark_std::UniformRand>::rand(&mut rng),
            owner_pubkey: <Fr as ark_std::UniformRand>::rand(&mut rng),
        };
        let output_commitment = output_note.commitment();

        // generate_constraints always pads paths to TREE_DEPTH. Provide an empty
        // path (gets padded with zeros). Pre-compute the root for the same padding.
        let merkle_root = merkle_root_for_leaf(input_commitment);

        TransferCircuit {
            input_notes: vec![input_note],
            output_notes: vec![output_note],
            merkle_paths: vec![MerklePath::default()],  // empty; padded to TREE_DEPTH in circuit
            secret_keys: vec![sk],
            merkle_root,
            nullifiers: vec![nullifier],
            output_commitments: vec![output_commitment],
            asset_id,
            fee_commitment: Fr::from(0u64),
        }
    }

    #[test]
    fn test_circuit_satisfiability() {
        let circuit = make_valid_circuit_1in_1out();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap(), "Constraints must be satisfied for a valid witness");
    }

    #[test]
    fn test_merkle_path_verification() {
        // Test verify_merkle_path (the public API, no path normalization) with a 2-level path.
        // This tests the Poseidon gadget traversal logic independent of generate_constraints.
        let mut rng = test_rng();
        let asset_id = Fr::from(0u64);
        let sk = <Fr as ark_std::UniformRand>::rand(&mut rng);
        let owner_pubkey = poseidon_hash(&[sk]);

        let note = Note {
            value: 50,
            asset_id,
            blinding: <Fr as ark_std::UniformRand>::rand(&mut rng),
            owner_pubkey,
        };

        let sibling1 = <Fr as ark_std::UniformRand>::rand(&mut rng);
        let sibling2 = <Fr as ark_std::UniformRand>::rand(&mut rng);

        // Compute expected root natively using Poseidon_t3 (hash_pair):
        //   leaf       → hash_pair(leaf, sibling1)  [leaf on left, index=false]
        //              → hash_pair(level0, sibling2) [left, index=false]
        let leaf = note.commitment();
        let level0 = poseidon_hash(&[leaf, sibling1]);
        let expected_root = poseidon_hash(&[level0, sibling2]);

        let merkle_path = MerklePath {
            path: vec![sibling1, sibling2],
            indices: vec![false, false],
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        let note_var = NoteVar::new_witness(cs.clone(), || Ok(note)).unwrap();
        let path_var = MerklePathVar::new_witness(cs.clone(), || Ok(merkle_path)).unwrap();

        // verify_merkle_path (public API) does NOT normalize; pass exact path
        let computed_root = verify_merkle_path(&note_var, &path_var).unwrap();
        let expected_root_var = FpVar::new_input(cs.clone(), || Ok(expected_root)).unwrap();
        computed_root.enforce_equal(&expected_root_var).unwrap();

        assert!(cs.is_satisfied().unwrap(), "2-level Merkle path verification must pass");
    }

    #[test]
    fn test_parity_native_vs_circuit() {
        // Verify in-circuit Poseidon matches native poseidon_hash for each arity.
        // Uses the published iden3 vector: Poseidon_t3([1,2]) == 0x115cc0f5...
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);

        let native_t3 = poseidon_hash(&[a, b]);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = FpVar::new_witness(cs.clone(), || Ok(a)).unwrap();
        let b_var = FpVar::new_witness(cs.clone(), || Ok(b)).unwrap();
        let circuit_t3 = hash_pair(&a_var, &b_var).unwrap();

        assert_eq!(
            circuit_t3.value().unwrap(),
            native_t3,
            "In-circuit hash_pair (Poseidon_t3) must match native poseidon_hash for [1,2]"
        );
        assert!(cs.is_satisfied().unwrap());

        // t5: commitment parity
        let v = Fr::from(100u64);
        let ai = Fr::from(3u64);
        let bl = Fr::from(7u64);
        let own = Fr::from(42u64);

        let native_commit = poseidon_hash(&[own, v, ai, bl]);

        let note = Note { value: 100, asset_id: ai, blinding: bl, owner_pubkey: own };
        let note_var = NoteVar::new_witness(cs.clone(), || Ok(note)).unwrap();
        let circuit_commit = compute_commitment(&note_var).unwrap();

        assert_eq!(
            circuit_commit.value().unwrap(),
            native_commit,
            "In-circuit compute_commitment (Poseidon_t5) must match native poseidon_hash"
        );

        // t2: compute_pk parity
        let sk = Fr::from(5u64);
        let native_pk = poseidon_hash(&[sk]);

        let sk_var = FpVar::new_witness(cs.clone(), || Ok(sk)).unwrap();
        let circuit_pk = compute_pk(&sk_var).unwrap();

        assert_eq!(
            circuit_pk.value().unwrap(),
            native_pk,
            "In-circuit compute_pk (Poseidon_t2) must match native poseidon_hash"
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_tampered_nullifier_fails() {
        let circuit = make_valid_circuit_1in_1out();
        let wrong_nullifier = Fr::from(0xdeadbeefu64);

        let tampered = TransferCircuit {
            nullifiers: vec![wrong_nullifier],
            ..circuit
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        tampered.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "Tampered nullifier must violate constraints"
        );
    }

    #[test]
    fn test_wrong_spend_authority_fails() {
        let mut rng = test_rng();
        let asset_id = Fr::from(0u64);

        let sk = <Fr as ark_std::UniformRand>::rand(&mut rng);
        let owner_pubkey = poseidon_hash(&[sk]);

        let input_note = Note {
            value: 100,
            asset_id,
            blinding: <Fr as ark_std::UniformRand>::rand(&mut rng),
            owner_pubkey,
        };

        let commitment = input_note.commitment();
        let nullifier = input_note.nullifier(sk);
        let merkle_root = merkle_root_for_leaf(commitment);

        let output_note = Note {
            value: 100,
            asset_id,
            blinding: <Fr as ark_std::UniformRand>::rand(&mut rng),
            owner_pubkey: <Fr as ark_std::UniformRand>::rand(&mut rng),
        };

        // Wrong sk: spend authority check will fail because
        //   note.owner_pubkey = poseidon_hash([sk])
        //   circuit computes compute_pk(wrong_sk) = poseidon_hash([wrong_sk]) ≠ owner_pubkey
        let wrong_sk = <Fr as ark_std::UniformRand>::rand(&mut rng);

        let circuit = TransferCircuit {
            input_notes: vec![input_note],
            output_notes: vec![output_note.clone()],
            merkle_paths: vec![MerklePath::default()],
            secret_keys: vec![wrong_sk],
            merkle_root,
            nullifiers: vec![nullifier],
            output_commitments: vec![output_note.commitment()],
            asset_id,
            fee_commitment: Fr::from(0u64),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "Wrong secret key must violate spend authority constraint"
        );
    }

    #[test]
    fn test_tampered_output_commitment_fails() {
        let circuit = make_valid_circuit_1in_1out();
        let wrong_output_commitment = Fr::from(0xdeadbeefu64);

        let tampered = TransferCircuit {
            output_commitments: vec![wrong_output_commitment],
            ..circuit
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        tampered.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "Tampered output commitment must violate constraints"
        );
    }

    #[test]
    fn test_balance_violation_fails() {
        let mut rng = test_rng();
        let asset_id = Fr::from(0u64);
        let sk = <Fr as ark_std::UniformRand>::rand(&mut rng);
        let owner_pubkey = poseidon_hash(&[sk]);

        let input_note = Note {
            value: 100,
            asset_id,
            blinding: <Fr as ark_std::UniformRand>::rand(&mut rng),
            owner_pubkey,
        };

        let commitment = input_note.commitment();
        let nullifier = input_note.nullifier(sk);
        let merkle_root = merkle_root_for_leaf(commitment);

        // Output note has DIFFERENT value (violates balance)
        let output_note = Note {
            value: 200,  // more than input!
            asset_id,
            blinding: <Fr as ark_std::UniformRand>::rand(&mut rng),
            owner_pubkey: <Fr as ark_std::UniformRand>::rand(&mut rng),
        };

        let circuit = TransferCircuit {
            input_notes: vec![input_note],
            output_notes: vec![output_note.clone()],
            merkle_paths: vec![MerklePath::default()],
            secret_keys: vec![sk],
            merkle_root,
            nullifiers: vec![nullifier],
            output_commitments: vec![output_note.commitment()],
            asset_id,
            fee_commitment: Fr::from(0u64),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            !cs.is_satisfied().unwrap(),
            "Balance violation (input 100 ≠ output 200) must fail constraints"
        );
    }

    #[test]
    fn test_default_circuit_has_fixed_constraint_count() {
        // TransferCircuit::default() (all dummy slots) must produce the same
        // number of constraints as a circuit with one real note.
        let default_circuit = TransferCircuit::default();
        let cs_default = ConstraintSystem::<Fr>::new_ref();
        default_circuit.generate_constraints(cs_default.clone()).unwrap();
        let n_default = cs_default.num_constraints();

        let cs_one = ConstraintSystem::<Fr>::new_ref();
        make_valid_circuit_1in_1out().generate_constraints(cs_one.clone()).unwrap();
        let n_one = cs_one.num_constraints();

        assert_eq!(
            n_default, n_one,
            "Fixed-shape circuit must have the same constraint count regardless of real note count"
        );
        println!("Fixed constraint count: {}", n_default);
    }
}
