//! Validator membership circuit implementation

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value, AssignedCell},
    plonk::{Circuit, ConstraintSystem, Error, Column, Instance, Advice, Selector},
    poly::Rotation,
};
use halo2curves::pasta::Fp;

use crate::VALIDATOR_TREE_DEPTH;

#[derive(Clone, Debug)]
pub struct MembershipConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    selector: Selector,
}

#[derive(Clone, Debug)]
pub struct ValidatorMembershipCircuit {
    // Public inputs
    pub validator_root: Fp,
    pub epoch: u64,
    pub slot: u64,

    // Private witness
    pub credential_secret: Fp,
    pub merkle_path: Vec<Fp>,
    pub merkle_indices: Vec<bool>,
}

impl ValidatorMembershipCircuit {
    pub fn new(
        validator_root: Fp,
        epoch: u64,
        slot: u64,
        credential_secret: Fp,
        merkle_path: Vec<Fp>,
        merkle_indices: Vec<bool>,
    ) -> Self {
        assert_eq!(merkle_path.len(), VALIDATOR_TREE_DEPTH);
        assert_eq!(merkle_indices.len(), VALIDATOR_TREE_DEPTH);

        Self {
            validator_root,
            epoch,
            slot,
            credential_secret,
            merkle_path,
            merkle_indices,
        }
    }

    pub fn dummy() -> Self {
        Self {
            validator_root: Fp::zero(),
            epoch: 0,
            slot: 0,
            credential_secret: Fp::zero(),
            merkle_path: vec![Fp::zero(); VALIDATOR_TREE_DEPTH],
            merkle_indices: vec![false; VALIDATOR_TREE_DEPTH],
        }
    }
}

impl Circuit<Fp> for ValidatorMembershipCircuit {
    type Config = MembershipConfig;
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

        // Enable equality on advice columns
        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);

        // Simple addition gate for demonstration
        meta.create_gate("add", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());

            vec![s * (a + b - c)]
        });

        MembershipConfig {
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
        // Compute credential commitment (simplified: just use the secret directly)
        let credential_commitment = self.credential_secret;

        // Assign validator_root and constrain to instance
        let root_cell = layouter.assign_region(
            || "validator_root",
            |mut region| {
                region.assign_advice(
                    || "root",
                    config.advice[0],
                    0,
                    || Value::known(self.validator_root),
                )
            },
        )?;
        layouter.constrain_instance(root_cell.cell(), config.instance, 0)?;

        // Assign epoch and constrain to instance
        let epoch_cell = layouter.assign_region(
            || "epoch",
            |mut region| {
                region.assign_advice(
                    || "epoch",
                    config.advice[0],
                    0,
                    || Value::known(Fp::from(self.epoch)),
                )
            },
        )?;
        layouter.constrain_instance(epoch_cell.cell(), config.instance, 1)?;

        // Assign slot and constrain to instance
        let slot_cell = layouter.assign_region(
            || "slot",
            |mut region| {
                region.assign_advice(
                    || "slot",
                    config.advice[0],
                    0,
                    || Value::known(Fp::from(self.slot)),
                )
            },
        )?;
        layouter.constrain_instance(slot_cell.cell(), config.instance, 2)?;

        // Verify Merkle path (simplified - just check root equals commitment for now)
        layouter.assign_region(
            || "verify_membership",
            |mut region| {
                let computed_root = region.assign_advice(
                    || "computed_root",
                    config.advice[0],
                    0,
                    || Value::known(credential_commitment),
                )?;

                let expected_root = region.assign_advice(
                    || "expected_root",
                    config.advice[1],
                    0,
                    || Value::known(self.validator_root),
                )?;

                region.constrain_equal(computed_root.cell(), expected_root.cell())?;

                Ok(())
            },
        )?;

        Ok(())
    }
}