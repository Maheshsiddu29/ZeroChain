//! Poseidon BN254 Parity Tests
//!
//! Validates that the ark-crypto-primitives backend (production) produces output
//! identical to light-poseidon (oracle) for each protocol arity:
//!
//!   t=2 (1-input), t=3 (2-input), t=5 (4-input)
//!
//! Both must match the published iden3/circom test vector:
//!   Poseidon_BN254_t3([Fr(1), Fr(2)]) =
//!     0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
//!
//! Sources: https://github.com/iden3/go-iden3-crypto/blob/master/poseidon/poseidon_test.go
//!          https://github.com/Lightprotocol/light-poseidon (bn254_x5 parameter set)

use zc_crypto::poseidon::{PoseidonHasher, poseidon_hash};
use zc_crypto::merkle::MerkleTree;
use ark_bn254::Fr;
use ark_ff::{PrimeField, BigInteger};

// ── helpers ──────────────────────────────────────────────────────────────────

fn hex_be_to_fr(hex_be: &str) -> Fr {
    let mut bytes_le = hex::decode(hex_be).expect("valid hex");
    bytes_le.reverse();
    bytes_le.resize(32, 0);
    Fr::from_le_bytes_mod_order(&bytes_le)
}

fn fr_to_hex_be(fr: Fr) -> String {
    let mut b = fr.into_bigint().to_bytes_le();
    b.resize(32, 0);
    b.reverse();
    hex::encode(b)
}

/// Run the light-poseidon oracle for a given t (number of inputs = t-1).
fn lp_hash(inputs: &[Fr]) -> Fr {
    use light_poseidon::PoseidonHasher as LpHasher;
    let mut h = light_poseidon::Poseidon::<Fr>::new_circom(inputs.len())
        .expect("valid circom arity");
    h.hash(inputs).expect("hash must not fail")
}

/// Run the ark-backed production hash for a given input slice.
fn ark_hash(inputs: &[Fr]) -> Fr {
    poseidon_hash(inputs)
}

// ── published vector ─────────────────────────────────────────────────────────

const IDEN3_VECTOR_1_2_HEX: &str =
    "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a";

#[test]
fn test_published_vector_iden3_t3_1_2() {
    // Poseidon_BN254_t3([Fr(1), Fr(2)]) == 0x115cc0f5…
    // This is the ground-truth commitment from iden3/go-iden3-crypto.
    let expected = hex_be_to_fr(IDEN3_VECTOR_1_2_HEX);
    let result = ark_hash(&[Fr::from(1u64), Fr::from(2u64)]);
    assert_eq!(
        result, expected,
        "ARK Poseidon_t3([1,2]) mismatch:\n  got      0x{}\n  expected 0x{}",
        fr_to_hex_be(result),
        fr_to_hex_be(expected),
    );
}

// ── arity parity: ark == light-poseidon ──────────────────────────────────────

#[test]
fn test_parity_t3_two_inputs() {
    // t=3 (2-input): Merkle node hash, nullifier hash
    for (a, b) in [(1u64, 2u64), (0, 0), (999, 1)] {
        let inputs = [Fr::from(a), Fr::from(b)];
        let ark = ark_hash(&inputs);
        let lp = lp_hash(&inputs);
        assert_eq!(
            ark, lp,
            "t=3 parity FAIL for [{}, {}]:\n  ark = 0x{}\n  lp  = 0x{}",
            a, b, fr_to_hex_be(ark), fr_to_hex_be(lp)
        );
    }
}

#[test]
fn test_parity_t5_four_inputs() {
    // t=5 (4-input): note commitment Poseidon(owner_pubkey, value, asset_id, blinding)
    for (a, b, c, d) in [
        (1u64, 2u64, 3u64, 4u64),
        (0, 0, 0, 0),
        (100, 0, 42, 7),
    ] {
        let inputs = [Fr::from(a), Fr::from(b), Fr::from(c), Fr::from(d)];
        let ark = ark_hash(&inputs);
        let lp = lp_hash(&inputs);
        assert_eq!(
            ark, lp,
            "t=5 parity FAIL for [{}, {}, {}, {}]:\n  ark = 0x{}\n  lp  = 0x{}",
            a, b, c, d, fr_to_hex_be(ark), fr_to_hex_be(lp)
        );
    }
}

#[test]
fn test_parity_t2_one_input() {
    // t=2 (1-input): pk = Poseidon(sk)
    for a in [0u64, 1, 42, 999] {
        let inputs = [Fr::from(a)];
        let ark = ark_hash(&inputs);
        let lp = lp_hash(&inputs);
        assert_eq!(
            ark, lp,
            "t=2 parity FAIL for [{}]:\n  ark = 0x{}\n  lp  = 0x{}",
            a, fr_to_hex_be(ark), fr_to_hex_be(lp)
        );
    }
}

// ── property tests ────────────────────────────────────────────────────────────

#[test]
fn test_hash_deterministic() {
    let h1 = ark_hash(&[Fr::from(1u64), Fr::from(2u64)]);
    let h2 = ark_hash(&[Fr::from(1u64), Fr::from(2u64)]);
    assert_eq!(h1, h2, "hash must be deterministic");
}

#[test]
fn test_hash_order_sensitive() {
    let a = Fr::from(1u64);
    let b = Fr::from(2u64);
    assert_ne!(
        ark_hash(&[a, b]),
        ark_hash(&[b, a]),
        "hash must be order-sensitive"
    );
}

#[test]
fn test_hash_four_differs_from_tree_reduction() {
    // t=5 4-input hash (fixed arity) must NOT equal the old tree-reduction
    // hash2(hash2(a,b), hash2(c,d)).  If they were equal it would mean the
    // commitment changed silently; if they differ it confirms we're using the
    // correct fixed-arity primitive.
    let (a, b, c, d) = (Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64));
    let fixed_arity = ark_hash(&[a, b, c, d]);
    let tree_reduced = ark_hash(&[ark_hash(&[a, b]), ark_hash(&[c, d])]);
    // These should be different — fixed arity t=5 ≠ tree reduction
    assert_ne!(
        fixed_arity, tree_reduced,
        "t=5 fixed-arity and tree-reduction should differ (different Poseidon instances)"
    );
}

#[test]
fn test_byte_level_api_roundtrip() {
    // PoseidonHasher::hash_two (byte API) must agree with poseidon_hash (Fr API)
    let a_bytes: [u8; 32] = { let mut b = [0u8; 32]; b[0] = 1; b };
    let b_bytes: [u8; 32] = { let mut b = [0u8; 32]; b[0] = 2; b };

    let byte_result = PoseidonHasher::hash_two(&a_bytes, &b_bytes);

    let a_fr = Fr::from_le_bytes_mod_order(&a_bytes);
    let b_fr = Fr::from_le_bytes_mod_order(&b_bytes);
    let fr_result = ark_hash(&[a_fr, b_fr]);

    let mut expected_bytes = [0u8; 32];
    let le = fr_result.into_bigint().to_bytes_le();
    expected_bytes[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);

    assert_eq!(
        byte_result, expected_bytes,
        "byte-level and Fr-level APIs must agree"
    );
}

#[test]
fn test_hash_four_byte_api_parity() {
    // PoseidonHasher::hash_four must agree with t=5 oracle
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];
    let d = [4u8; 32];

    let byte_result = PoseidonHasher::hash_four(&a, &b, &c, &d);

    let inputs: Vec<Fr> = [a, b, c, d]
        .iter()
        .map(|x| Fr::from_le_bytes_mod_order(x))
        .collect();
    let lp = lp_hash(&inputs);
    let mut lp_bytes = [0u8; 32];
    let le = lp.into_bigint().to_bytes_le();
    lp_bytes[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);

    assert_eq!(
        byte_result, lp_bytes,
        "hash_four byte API must match light-poseidon t=5"
    );
}

#[test]
fn test_collision_resistance() {
    let pairs = [
        ([0u8; 32], [0u8; 32]),
        ([0u8; 32], [1u8; 32]),
        ([1u8; 32], [0u8; 32]),
        ([1u8; 32], [1u8; 32]),
    ];
    let mut hashes = std::collections::HashSet::new();
    for (a, b) in &pairs {
        let hash = PoseidonHasher::hash_two(a, b);
        assert!(hashes.insert(hash), "Hash collision detected!");
    }
}

#[test]
fn test_merkle_root_computation() {
    let leaves: Vec<[u8; 32]> =
        (0..4u8).map(|i| { let mut l = [0u8; 32]; l[0] = i; l }).collect();
    let tree = MerkleTree::new(&leaves);
    let root = tree.root();
    let proof = tree.proof(0);
    assert!(MerkleTree::verify_proof(&root, &leaves[0], &proof));
}
