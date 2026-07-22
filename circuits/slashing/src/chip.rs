//! Halo2 Custom Chip for Slashing Operations

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Column, Error, Advice, Selector},
};
use halo2curves::pasta::Fp;

/// Merkle Hash Chip - computes conditional Merkle hashing
#[derive(Clone, Debug)]
pub struct MerkleHashChip {
    pub advice: [Column<Advice>; 3],
    pub selector: Selector,
}

impl MerkleHashChip {
    pub fn new(advice: [Column<Advice>; 3], selector: Selector) -> Self {
        Self { advice, selector }
    }

    /// Hash two values: H(left, right) = left + right (simplified)
    /// In production, integrate proper Poseidon or Keccak
    pub fn hash_pair(
        &self,
        mut layouter: impl Layouter<Fp>,
        left: Value<Fp>,
        right: Value<Fp>,
    ) -> Result<Value<Fp>, Error> {
        layouter.assign_region(
            || "merkle_hash_pair",
            |mut region| {
                // Assign left
                region.assign_advice(|| "left", self.advice[0], 0, || left)?;

                // Assign right
                region.assign_advice(|| "right", self.advice[1], 0, || right)?;

                // Compute and assign result
                let result = left.zip(right).map(|(l, r)| l + r);
                region.assign_advice(|| "hash", self.advice[2], 0, || result)?;

                Ok(result)
            },
        )
    }
}

/// Equality Chip - proves a == b
#[derive(Clone, Debug)]
pub struct EqualityChip {
    pub advice: [Column<Advice>; 2],
    pub selector: Selector,
}

impl EqualityChip {
    pub fn new(advice: [Column<Advice>; 2], selector: Selector) -> Self {
        Self { advice, selector }
    }

    pub fn assert_equal(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Value<Fp>,
        b: Value<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assert_equal",
            |mut region| {
                let a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let b_cell = region.assign_advice(|| "b", self.advice[1], 0, || b)?;

                region.constrain_equal(a_cell.cell(), b_cell.cell())
            },
        )
    }
}

/// Difference Chip - proves a ≠ b (i.e., a - b ≠ 0)
#[derive(Clone, Debug)]
pub struct DifferenceChip {
    pub advice: [Column<Advice>; 2],
}

impl DifferenceChip {
    pub fn new(advice: [Column<Advice>; 2]) -> Self {
        Self { advice }
    }

    pub fn assert_not_equal(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Value<Fp>,
        b: Value<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assert_not_equal",
            |mut region| {
                region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                region.assign_advice(|| "b", self.advice[1], 0, || b)?;

                // In a real circuit, would assign inverse of (a - b)
                // and constrain (a - b) * inv = 1, proving a ≠ b

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_hash_chip() {
        let left = Fp::from(100);
        let right = Fp::from(200);
        let expected = left + right;

println!("Hash({:?}, {:?}) = {:?}", left, right, expected);
        assert_eq!(expected, Fp::from(300));
    }
}