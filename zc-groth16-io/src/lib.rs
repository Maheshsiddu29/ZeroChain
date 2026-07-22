//! Host function interface for BN254 Groth16 verification.
//!
//! `#[runtime_interface]` generates:
//! - For native (std): a real arkworks BN254 Groth16 verification call.
//! - For WASM (no_std): an extern FFI call fulfilled by the node executor.
//!
//! `verify_bn254` accepts a single packed byte slice with this layout
//! (all sizes fixed for BN254 / the fixed-shape TransferCircuit):
//!
//! ```text
//! bytes  0 ..  64  : proof_a  (uncompressed BN254 G1, 64 bytes)
//! bytes 64 .. 192  : proof_b  (uncompressed BN254 G2, 128 bytes)
//! bytes 192 .. 256  : proof_c  (uncompressed BN254 G1, 64 bytes)
//! bytes 256 .. 260  : vk_len  (u32 little-endian)
//! bytes 260 .. 260+vk_len : vk bytes
//! bytes 260+vk_len ..    : public_inputs_flat (19 × 32 = 608 bytes, LE field elements)
//! ```
//!
//! Returns `false` for any failure: bad curve points, non-canonical field encoding
//! (C-01/H-13), wrong public-input count, or proof rejection.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

/// Pack the Groth16 verification request into the flat byte layout expected by `verify_bn254`.
///
/// Exposed here so both the pallet (WASM) and any test callers use the same encoding.
#[cfg(feature = "std")]
pub fn pack_request(
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    vk: &[u8],
    public_inputs_flat: &[u8],
) -> std::vec::Vec<u8> {
    let vk_len = vk.len() as u32;
    let mut buf = std::vec::Vec::with_capacity(256 + 4 + vk.len() + public_inputs_flat.len());
    buf.extend_from_slice(proof_a);
    buf.extend_from_slice(proof_b);
    buf.extend_from_slice(proof_c);
    buf.extend_from_slice(&vk_len.to_le_bytes());
    buf.extend_from_slice(vk);
    buf.extend_from_slice(public_inputs_flat);
    buf
}

/// no_std version of `pack_request` for the WASM path in the pallet.
#[cfg(not(feature = "std"))]
pub fn pack_request(
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    vk: &[u8],
    public_inputs_flat: &[u8],
) -> alloc::vec::Vec<u8> {
    let vk_len = vk.len() as u32;
    let mut buf = alloc::vec::Vec::with_capacity(256 + 4 + vk.len() + public_inputs_flat.len());
    buf.extend_from_slice(proof_a);
    buf.extend_from_slice(proof_b);
    buf.extend_from_slice(proof_c);
    buf.extend_from_slice(&vk_len.to_le_bytes());
    buf.extend_from_slice(vk);
    buf.extend_from_slice(public_inputs_flat);
    buf
}

/// BN254 Groth16 host function.
///
/// Uses `PassFatPointerAndRead<&[u8]>` so the macro passes the buffer as a fat-pointer
/// (ptr+len) across the WASM/native FFI boundary without needing `Vec` in the parameter
/// type (which would be unresolved in no_std). The function body receives the inner
/// `&[u8]` directly.
#[sp_runtime_interface::runtime_interface]
pub trait ZcGroth16 {
    fn verify_bn254(request: sp_runtime_interface::pass_by::PassFatPointerAndRead<&[u8]>) -> bool {
        use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
        use ark_groth16::{Groth16, Proof, VerifyingKey};
        use ark_serialize::CanonicalDeserialize;
        use ark_snark::SNARK;

        if request.len() < 260 {
            return false;
        }
        let proof_a = &request[0..64];
        let proof_b = &request[64..192];
        let proof_c = &request[192..256];
        let vk_len = u32::from_le_bytes([request[256], request[257], request[258], request[259]]) as usize;
        if request.len() < 260 + vk_len {
            return false;
        }
        let vk_bytes = &request[260..260 + vk_len];
        let public_inputs_flat = &request[260 + vk_len..];

        // Canonical proof-point deserialization — also performs subgroup checks (H-13)
        let a = match G1Affine::deserialize_uncompressed(proof_a) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let b = match G2Affine::deserialize_uncompressed(proof_b) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let c = match G1Affine::deserialize_uncompressed(proof_c) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let ark_proof = Proof::<Bn254> { a, b, c };

        let ark_vk = match VerifyingKey::<Bn254>::deserialize_uncompressed(vk_bytes) {
            Ok(v) => v,
            Err(_) => return false,
        };

        // Parse public inputs: reject non-canonical field encodings (C-01/H-13)
        if public_inputs_flat.len() % 32 != 0 {
            return false;
        }
        let mut fr_inputs = std::vec::Vec::new();
        for chunk in public_inputs_flat.chunks(32) {
            match Fr::deserialize_uncompressed(chunk) {
                Ok(fr) => fr_inputs.push(fr),
                Err(_) => return false,
            }
        }

        let pvk = ark_groth16::prepare_verifying_key(&ark_vk);
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &fr_inputs, &ark_proof)
            .unwrap_or(false)
    }
}
