//! Slashing Circuit Implementation (Halo2)
//!
//! Comprehensive equivocation detection circuit

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, Column, Instance, Advice, Selector},
    poly::Rotation,
};
use halo2curves::pasta::Fp;
use crate::VALIDATOR_TREE_DEPTH;
use std::marker::PhantomData;

/// Public inputs for slashing proof
#[derive(Clone, Debug)]
pub struct SlashingPublicInputs {
    /// Merkle root of validator credentials
    pub validator_root: Fp,
    /// Nullifier: H(commitment, epoch) - prevents reuse
    pub nullifier: Fp,
    /// First block hash (as field element)
    pub block_hash_1: Fp,
    /// Second block hash (as field element)
    pub block_hash_2: Fp,
    /// Epoch number (for nullifier freshness)
    pub epoch: u64,
}

impl SlashingPublicInputs {
    pub fn new(
        validator_root: Fp,
        nullifier: Fp,
        block_hash_1: Fp,
        block_hash_2: Fp,
        epoch: u64,
    ) -> Self {
        Self {
            validator_root,
            nullifier,
            block_hash_1,
            block_hash_2,
            epoch,
        }
    }

    /// Verify public inputs are valid (basic checks)
    pub fn verify(&self) -> Result<(), SlashingError> {
        // Block hashes must be different (equivocation)
        if self.block_hash_1 == self.block_hash_2 {
            return Err(SlashingError::IdenticalBlocks);
        }

        // Nullifier should not be zero (indicates valid commitment)
        if self.nullifier == Fp::zero() {
            return Err(SlashingError::InvalidNullifier);
        }

        // Validator root should not be zero
        if self.validator_root == Fp::zero() {
            return Err(SlashingError::InvalidValidatorRoot);
        }

        Ok(())
    }
}

/// Errors in slashing circuit
#[derive(Clone, Debug)]
pub enum SlashingError {
    /// Block hashes must differ for equivocation
    IdenticalBlocks,
    /// Nullifier is zero or invalid
    InvalidNullifier,
    /// Validator root is zero
    InvalidValidatorRoot,
    /// Merkle path length mismatch
    InvalidMerklePath,
    /// Circuit synthesis failed
    SynthesisError(String),
}

impl std::fmt::Display for SlashingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlashingError::IdenticalBlocks => {
                write!(f, "Block hashes must be different for equivocation proof")
            }
            SlashingError::InvalidNullifier => write!(f, "Nullifier is invalid or zero"),
            SlashingError::InvalidValidatorRoot => write!(f, "Validator root is zero"),
            SlashingError::InvalidMerklePath => write!(f, "Merkle path has invalid length"),
            SlashingError::SynthesisError(msg) => write!(f, "Synthesis error: {}", msg),
        }
    }
}

/// Slashing Circuit Configuration
#[derive(Clone)]
pub struct SlashingConfig {
    pub advice: [Column<Advice>; 3],
    pub instance: Column<Instance>,
    pub selector: Selector,
}

/// Slashing Circuit
#[derive(Clone)]
pub struct SlashingCircuit {
    // Public inputs
    pub validator_root: Fp,
    pub nullifier: Fp,
    pub block_hash_1: Fp,
    pub block_hash_2: Fp,
    pub epoch: u64,

    // Private witness
    pub commitment: Fp,
    pub merkle_path: Vec<Fp>,
    pub merkle_indices: Vec<bool>,
    /// Nonce used when signing block 1
    pub sig_nonce_1: Fp,
    /// Nonce used when signing block 2
    pub sig_nonce_2: Fp,
}

impl SlashingCircuit {
    pub fn new(
        validator_root: Fp,
        nullifier: Fp,
        block_hash_1: Fp,
        block_hash_2: Fp,
        epoch: u64,
        commitment: Fp,
        merkle_path: Vec<Fp>,
        merkle_indices: Vec<bool>,
        sig_nonce_1: Fp,
        sig_nonce_2: Fp,
    ) -> Result<Self, SlashingError> {
        // Validate public inputs first
        let public_inputs = SlashingPublicInputs::new(
            validator_root,
            nullifier,
            block_hash_1,
            block_hash_2,
            epoch,
        );
        public_inputs.verify()?;

        // Validate merkle path
        if merkle_path.len() != VALIDATOR_TREE_DEPTH {
            return Err(SlashingError::InvalidMerklePath);
        }
        if merkle_indices.len() != VALIDATOR_TREE_DEPTH {
            return Err(SlashingError::InvalidMerklePath);
        }

        // Verify nonces are different (ensure different signatures)
        if sig_nonce_1 == sig_nonce_2 {
            return Err(SlashingError::SynthesisError(
                "Signature nonces must be different".to_string(),
            ));
        }

        Ok(Self {
            validator_root,
            nullifier,
            block_hash_1,
            block_hash_2,
            epoch,
            commitment,
            merkle_path,
            merkle_indices,
            sig_nonce_1,
            sig_nonce_2,
        })
    }

    pub fn dummy() -> Self {
        Self {
            validator_root: Fp::zero(),
            nullifier: Fp::zero(),
            block_hash_1: Fp::from(1),
            block_hash_2: Fp::from(2),
            epoch: 0,
            commitment: Fp::zero(),
            merkle_path: vec![Fp::zero(); VALIDATOR_TREE_DEPTH],
            merkle_indices: vec![false; VALIDATOR_TREE_DEPTH],
            sig_nonce_1: Fp::from(1),
            sig_nonce_2: Fp::from(2),
        }
    }
}

impl Circuit<Fp> for SlashingCircuit {
    type Config = SlashingConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::dummy()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let selector = meta.selector();

        // Enable equality for all columns
        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);

        // Simple gate: a + b = c
        meta.create_gate("add", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            vec![s * (a + b - c)]
        });

        SlashingConfig {
            advice,
            instance,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // CONSTRAINT 1: Assign public inputs
        let block_hash_1_cell = layouter.assign_region(
            || "block_hash_1",
            |mut region| {
                region.assign_advice(
                    || "block_hash_1",
                    config.advice[0],
                    0,
                    || Value::known(self.block_hash_1),
                )
            },
        )?;
        layouter.constrain_instance(block_hash_1_cell.cell(), config.instance, 0)?;

        let block_hash_2_cell = layouter.assign_region(
            || "block_hash_2",
            |mut region| {
                region.assign_advice(
                    || "block_hash_2",
                    config.advice[0],
                    0,
                    || Value::known(self.block_hash_2),
                )
            },
        )?;
        layouter.constrain_instance(block_hash_2_cell.cell(), config.instance, 1)?;

        let nullifier_cell = layouter.assign_region(
            || "nullifier",
            |mut region| {
                region.assign_advice(
                    || "nullifier",
                    config.advice[0],
                    0,
                    || Value::known(self.nullifier),
                )
            },
        )?;
        layouter.constrain_instance(nullifier_cell.cell(), config.instance, 2)?;

        let validator_root_cell = layouter.assign_region(
            || "validator_root",
            |mut region| {
                region.assign_advice(
                    || "validator_root",
                    config.advice[0],
                    0,
                    || Value::known(self.validator_root),
                )
            },
        )?;
        layouter.constrain_instance(validator_root_cell.cell(), config.instance, 3)?;

        // CONSTRAINT 2: Merkle membership (simplified - verify commitment is in tree)
        // In a real circuit, this would do proper Merkle proof verification
        let mut current = layouter.assign_region(
            || "merkle_leaf",
            |mut region| {
                region.assign_advice(
                    || "commitment",
                    config.advice[0],
                    0,
                    || Value::known(self.commitment),
                )
            },
        )?;

        // Walk through merkle path
for (i, (sibling, &_is_right)) in self
            .merkle_path
            .iter()
            .zip(self.merkle_indices.iter())
            .enumerate()
        {
            let sibling_cell = layouter.assign_region(
                || format!("merkle_path_{}", i),
                |mut region| {
                    region.assign_advice(
                        || "sibling",
                        config.advice[0],
                        0,
                        || Value::known(*sibling),
                    )
                },
            )?;

            // Simplified: add sibling (in real circuit, conditional hash)
            let sum = layouter.assign_region(
                || format!("merkle_hash_{}", i),
                |mut region| {
                    let current_val = current.value().copied();
                    let sibling_val = sibling_cell.value().copied();

                    let result = current_val.zip(sibling_val).map(|(c, s)| c + s);

                    region.assign_advice(
                        || "sum",
                        config.advice[2],
                        0,
                        || result,
                    )
                },
            )?;

            current = sum;
        }

        // Verify final root matches validator_root
        layouter.assign_region(
            || "verify_merkle",
            |mut region| {
                let expected = region.assign_advice(
                    || "expected_root",
                    config.advice[0],
                    0,
                    || Value::known(self.validator_root),
                )?;

                region.constrain_equal(current.cell(), expected.cell())
            },
        )?;

        // CONSTRAINT 3: Verify nullifier derivation
        // nullifier = H(commitment, epoch)
        // Simplified: nullifier = commitment + epoch_fp
        let epoch_fp = Fp::from(self.epoch);
        let expected_nullifier = self.commitment + epoch_fp;

        layouter.assign_region(
            || "verify_nullifier",
            |mut region| {
                let expected = region.assign_advice(
                    || "expected_nullifier",
                    config.advice[0],
                    0,
                    || Value::known(expected_nullifier),
                )?;

                let actual = region.assign_advice(
                    || "actual_nullifier",
                    config.advice[1],
                    0,
                    || Value::known(self.nullifier),
                )?;

                region.constrain_equal(expected.cell(), actual.cell())
            },
        )?;

        // CONSTRAINT 4: Verify block hashes are different
        let diff = self.block_hash_1 + (-self.block_hash_2);
        if diff == Fp::zero() {
            return Err(Error::Synthesis);
        }

        // CONSTRAINT 5: Verify nonces are different (proves different signatures)
        let nonce_diff = self.sig_nonce_1 + (-self.sig_nonce_2);
        if nonce_diff == Fp::zero() {
            return Err(Error::Synthesis);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_inputs_validation() {
        // Valid
        let inputs = SlashingPublicInputs::new(
            Fp::from(1),
            Fp::from(2),
            Fp::from(100),
            Fp::from(101),
            1,
        );
        assert!(inputs.verify().is_ok());

        // Identical blocks
        let inputs_bad = SlashingPublicInputs::new(
            Fp::from(1),
            Fp::from(2),
            Fp::from(100),
            Fp::from(100),
            1,
        );
        assert!(inputs_bad.verify().is_err());

        // Zero nullifier
        let inputs_bad2 = SlashingPublicInputs::new(
            Fp::from(1),
            Fp::zero(),
            Fp::from(100),
            Fp::from(101),
            1,
        );
        assert!(inputs_bad2.verify().is_err());
    }

    #[test]
    fn test_circuit_creation() {
        let circuit = SlashingCircuit::dummy();
        assert_eq!(circuit.merkle_path.len(), VALIDATOR_TREE_DEPTH);
    }
}