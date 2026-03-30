//! Circuit configuration and chip definitions

use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Fixed, Instance, Selector},
};
use halo2curves::pasta::Fp;

use crate::poseidon_chip::PoseidonConfig;

/// Main configuration for the membership circuit
#[derive(Clone, Debug)]
pub struct MembershipConfig {
    /// Advice columns for witness values
    pub advice: [Column<Advice>; 3],
    
    /// Instance column for public inputs
    pub instance: Column<Instance>,
    
    /// Fixed column for constants
    pub fixed: Column<Fixed>,
    
    /// Selector for equality constraints
    pub s_eq: Selector,
    
    /// Poseidon hash configuration
    pub poseidon_config: PoseidonConfig,
}

impl MembershipConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // Create columns
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let fixed = meta.fixed_column();
        let s_eq = meta.selector();
        
        // Enable equality for all advice columns
        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);
        
        // Configure Poseidon chip
        let poseidon_config = PoseidonConfig::configure(
            meta,
            advice[0],
            advice[1],
            advice[2],
            fixed,
        );
        
        // Equality gate
        meta.create_gate("equality", |meta| {
            let s = meta.query_selector(s_eq);
            let a = meta.query_advice(advice[0], halo2_proofs::poly::Rotation::cur());
            let b = meta.query_advice(advice[1], halo2_proofs::poly::Rotation::cur());
            
            vec![s * (a - b)]
        });
        
        Self {
            advice,
            instance,
            fixed,
            s_eq,
            poseidon_config,
        }
    }
}