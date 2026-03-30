//! Halo2 Validator Membership Circuit
//! 
//! Proves: "I know a validator credential that is in the Merkle tree with root R,
//!          without revealing which validator I am."
//! 
//! Public Inputs:
//! - validator_root: Merkle root of the validator credential tree
//! - epoch: Current epoch number (for replay protection)
//! - slot: Current slot number
//! 
//! Private Witness:
//! - credential_secret: The validator's secret key
//! - merkle_path: Siblings in the Merkle tree
//! - merkle_indices: Left/right directions in the path

pub mod circuit;
pub mod chip;
pub mod poseidon_chip;

pub use circuit::ValidatorMembershipCircuit;
pub use chip::MembershipConfig;

use halo2_proofs::{
    plonk::{Circuit, ConstraintSystem, Error, ProvingKey, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Blake2bRead, Challenge255},
};
use halo2curves::pasta::{Fp, EqAffine};
use rand::rngs::OsRng;

/// Depth of the validator Merkle tree
pub const VALIDATOR_TREE_DEPTH: usize = 20; // Supports ~1M validators

/// Generate proving and verifying keys
pub fn setup(k: u32) -> Result<(ProvingKey<EqAffine>, VerifyingKey<EqAffine>), Error> {
    let params = Params::<EqAffine>::new(k);
    let circuit = ValidatorMembershipCircuit::dummy();
    
    let vk = halo2_proofs::plonk::keygen_vk(&params, &circuit)?;
    let pk = halo2_proofs::plonk::keygen_pk(&params, vk.clone(), &circuit)?;
    
    Ok((pk, vk))
}

/// Generate a proof
pub fn prove(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: ValidatorMembershipCircuit,
    public_inputs: &[Fp],
) -> Result<Vec<u8>, Error> {
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    
    halo2_proofs::plonk::create_proof(
        params,
        pk,
        &[circuit],
        &[&[public_inputs]],
        OsRng,
        &mut transcript,
    )?;
    
    Ok(transcript.finalize())
}

/// Verify a proof
pub fn verify(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    proof: &[u8],
    public_inputs: &[Fp],
) -> Result<bool, Error> {
    let strategy = halo2_proofs::plonk::SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
    
    halo2_proofs::plonk::verify_proof(
        params,
        vk,
        strategy,
        &[&[public_inputs]],
        &mut transcript,
    ).map(|_| true)
    .or_else(|_| Ok(false))
}