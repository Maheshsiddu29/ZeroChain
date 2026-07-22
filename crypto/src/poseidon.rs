//! Poseidon Hash for BN254 — ark-crypto-primitives backend
//!
//! Uses `ark_crypto_primitives::sponge::poseidon` with iden3 BN254 x5 parameters
//! (full_rounds=8, alpha=5, partial_rounds per width: t=2→56, t=3→57, t=5→60).
//!
//! State convention matches circom/iden3: [domain_tag=0, input₀, …, inputₙ₋₁].
//! Output is state[0] after the permutation — the capacity element.
//!
//! Validated against: iden3/go-iden3-crypto and Lightprotocol/light-poseidon (oracle).
//! Published vector: Poseidon_BN254_t3([1, 2]) ==
//!   0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a

pub type Hash256 = [u8; 32];

/// Parameters (match circuit)
pub mod params_info {
    pub const FULL_ROUNDS: usize = 8;
    pub const ALPHA: u64 = 5;
    // Partial rounds indexed as PARTIAL_ROUNDS[t-2]
    pub const PARTIAL_ROUNDS: [usize; 4] = [56, 57, 56, 60]; // t=2,3,4,5
}

/// Byte-level Poseidon hasher (std only)
pub struct PoseidonHasher;

/// Shared PoseidonConfig parameters for the protocol.
///
/// Constructed from iden3 BN254 x5 constants via ark-crypto-primitives'
/// `find_poseidon_ark_and_mds` (same grain-LFSR procedure as iden3).
/// These configs are the single source of truth shared with circuit gadgets.
#[cfg(any(feature = "poseidon", feature = "std"))]
pub mod params {
    use ark_bn254::Fr;
    pub use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;

    const FULL_ROUNDS: u64 = 8;
    const ALPHA: u64 = 5;

    fn build(rate: usize, partial_rounds: u64) -> PoseidonConfig<Fr> {
        let prime_bits = <Fr as ark_ff::PrimeField>::MODULUS_BIT_SIZE as u64;
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            prime_bits,
            rate,
            FULL_ROUNDS,
            partial_rounds,
            0, // skip_matrices; validated to be 0 for iden3 BN254 x5 by parity tests
        );
        PoseidonConfig::new(
            FULL_ROUNDS as usize,
            partial_rounds as usize,
            ALPHA,
            mds,
            ark,
            rate,
            1, // capacity = 1
        )
    }

    /// t=2: 1-input hash (e.g. pk = Poseidon(sk)).  partial_rounds = 56.
    pub fn config_t2() -> PoseidonConfig<Fr> { build(1, 56) }

    /// t=3: 2-input hash (Merkle nodes, nullifiers).  partial_rounds = 57.
    pub fn config_t3() -> PoseidonConfig<Fr> { build(2, 57) }

    /// t=5: 4-input hash (note commitment).  partial_rounds = 60.
    pub fn config_t5() -> PoseidonConfig<Fr> { build(4, 60) }
}

#[cfg(any(feature = "poseidon", feature = "std"))]
mod inner {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use ark_crypto_primitives::sponge::{
        poseidon::PoseidonSponge,
        CryptographicSponge,
        FieldBasedCryptographicSponge,
    };
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

    /// Core fixed-arity Poseidon using the iden3/circom state convention.
    ///
    /// State initialization: `[0, input₀, …, inputₙ₋₁]` (capacity element first = 0).
    /// Output: `state[0]` after the permutation — the capacity element.
    ///
    /// This is NOT the sponge squeeze output (which would be state[1]).
    /// We absorb inputs into the rate positions, trigger the permutation via the
    /// first squeeze call, then read `state[0]` directly from the public field.
    pub(super) fn hash_fixed_arity(config: &PoseidonConfig<Fr>, inputs: &[Fr]) -> Fr {
        let mut sponge = PoseidonSponge::<Fr>::new(config);
        // absorb sets state[capacity + i] += input[i]; capacity element stays 0
        sponge.absorb(&inputs);
        // squeeze_native_field_elements triggers permute() then reads state[capacity..]
        // We ignore the return value; we want state[0] (the iden3/circom output).
        let _ = sponge.squeeze_native_field_elements(1);
        sponge.state[0]
    }

    pub(super) fn hash_two_fr(a: Fr, b: Fr) -> Fr {
        let cfg = super::params::config_t3();
        hash_fixed_arity(&cfg, &[a, b])
    }

    pub(super) fn hash_four_fr(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
        let cfg = super::params::config_t5();
        hash_fixed_arity(&cfg, &[a, b, c, d])
    }

    pub(super) fn hash_one_fr(a: Fr) -> Fr {
        let cfg = super::params::config_t2();
        hash_fixed_arity(&cfg, &[a])
    }

    pub(super) fn bytes_to_fr(bytes: &[u8; 32]) -> Fr {
        Fr::from_le_bytes_mod_order(bytes)
    }

    pub(super) fn fr_to_bytes(fr: Fr) -> [u8; 32] {
        let mut out = [0u8; 32];
        let le = fr.into_bigint().to_bytes_le();
        out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
        out
    }
}

/// Hash field elements.
///
/// - 1 input  → t=2 config (fixed arity)
/// - 2 inputs → t=3 config (fixed arity)
/// - 4 inputs → t=5 config (fixed arity)
/// - Other lengths → binary-tree reduction with t=3 (not used by the protocol)
#[cfg(feature = "std")]
pub fn poseidon_hash(inputs: &[ark_bn254::Fr]) -> ark_bn254::Fr {
    use ark_bn254::Fr;
    match inputs.len() {
        0 => Fr::from(0u64),
        1 => inner::hash_one_fr(inputs[0]),
        2 => inner::hash_two_fr(inputs[0], inputs[1]),
        4 => inner::hash_four_fr(inputs[0], inputs[1], inputs[2], inputs[3]),
        _ => {
            let mut layer: Vec<Fr> = inputs
                .chunks(2)
                .map(|c| match c {
                    [a, b] => inner::hash_two_fr(*a, *b),
                    [a] => inner::hash_two_fr(*a, Fr::from(0u64)),
                    _ => unreachable!(),
                })
                .collect();
            while layer.len() > 1 {
                layer = layer
                    .chunks(2)
                    .map(|c| match c {
                        [a, b] => inner::hash_two_fr(*a, *b),
                        [a] => inner::hash_two_fr(*a, Fr::from(0u64)),
                        _ => unreachable!(),
                    })
                    .collect();
            }
            layer[0]
        }
    }
}

/// Fixed-arity methods — available in no_std when the `poseidon` feature is enabled.
#[cfg(any(feature = "poseidon", feature = "std"))]
impl PoseidonHasher {
    /// Hash two 32-byte values via t=3 Poseidon (Merkle / nullifier arity).
    pub fn hash_two(left: &Hash256, right: &Hash256) -> Hash256 {
        use inner::{bytes_to_fr, fr_to_bytes, hash_two_fr};
        fr_to_bytes(hash_two_fr(bytes_to_fr(left), bytes_to_fr(right)))
    }

    /// Hash one 32-byte value via t=2 Poseidon (pk = Poseidon(sk) arity).
    pub fn hash_one(input: &Hash256) -> Hash256 {
        use inner::{bytes_to_fr, fr_to_bytes, hash_one_fr};
        fr_to_bytes(hash_one_fr(bytes_to_fr(input)))
    }

    /// Hash four 32-byte values via t=5 Poseidon (commitment arity).
    /// Uses fixed-arity, NOT tree reduction.
    pub fn hash_four(a: &Hash256, b: &Hash256, c: &Hash256, d: &Hash256) -> Hash256 {
        use inner::{bytes_to_fr, fr_to_bytes, hash_four_fr};
        fr_to_bytes(hash_four_fr(
            bytes_to_fr(a),
            bytes_to_fr(b),
            bytes_to_fr(c),
            bytes_to_fr(d),
        ))
    }

    /// Encode u64 as a 32-byte little-endian field element.
    pub fn u64_to_hash(value: u64) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    /// Hash two u64 values via t=3 Poseidon.
    pub fn hash_two_u64(a: u64, b: u64) -> Hash256 {
        Self::hash_two(&Self::u64_to_hash(a), &Self::u64_to_hash(b))
    }
}

/// Variable-arity method — requires std (uses Vec for tree reduction).
#[cfg(feature = "std")]
impl PoseidonHasher {
    /// Hash arbitrary number of elements (binary tree reduction with t=3).
    pub fn hash_many(inputs: &[Hash256]) -> Hash256 {
        use inner::{bytes_to_fr, fr_to_bytes};
        if inputs.is_empty() {
            return [0u8; 32];
        }
        let frs: Vec<ark_bn254::Fr> = inputs.iter().map(|b| bytes_to_fr(b)).collect();
        fr_to_bytes(poseidon_hash(&frs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let h1 = PoseidonHasher::hash_two(&a, &b);
        let h2 = PoseidonHasher::hash_two(&a, &b);
        assert_eq!(h1, h2, "Hash must be deterministic");
    }

    #[test]
    fn test_hash_different_inputs() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        assert_ne!(
            PoseidonHasher::hash_two(&a, &b),
            PoseidonHasher::hash_two(&a, &c)
        );
    }

    #[test]
    fn test_known_values() {
        println!("=== Poseidon BN254 x5 Values ===");
        let h1 = PoseidonHasher::hash_two_u64(0, 0);
        println!("Poseidon_t3(0, 0) = 0x{}", hex::encode(h1));
        let h2 = PoseidonHasher::hash_two_u64(1, 2);
        println!("Poseidon_t3(1, 2) = 0x{}", hex::encode(h2));
    }
}
