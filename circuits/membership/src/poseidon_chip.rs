//! Poseidon hash chip for Halo2
//!
//! Simplified implementation - for production use a proper Poseidon gadget

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Error, Column, Advice},
};
use halo2curves::pasta::Fp;

#[derive(Clone, Debug)]
pub struct PoseidonChip {
    advice: [Column<Advice>; 3],
}

impl PoseidonChip {
    pub fn new(advice: [Column<Advice>; 3]) -> Self {
        Self { advice }
    }

    /// Hash two field elements (simplified)
    pub fn hash_two(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Value<Fp>,
        b: Value<Fp>,
    ) -> Result<Value<Fp>, Error> {
        // Simplified: just add them (replace with proper Poseidon in production)
        layouter.assign_region(
            || "poseidon_hash",
            |mut region| {
                let _a_val = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let _b_val = region.assign_advice(|| "b", self.advice[1], 0, || b)?;

                let result = a.zip(b).map(|(a, b)| a + b);

                region.assign_advice(|| "result", self.advice[2], 0, || result)?;

                Ok(result)
            },
        )
    }
}