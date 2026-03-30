//! Poseidon hash implementation for BN254 scalar field
//! 
//! CRITICAL: These parameters MUST be shared with crypto/ crate.
//! Akshay must use the exact same parameters in crypto/src/poseidon.rs

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};

/// Poseidon parameters for BN254 - t=3 (rate=2, capacity=1)
pub mod params {
    use super::*;
    
    pub const WIDTH: usize = 3;
    pub const RATE: usize = 2;
    pub const CAPACITY: usize = 1;
    pub const FULL_ROUNDS: usize = 8;
    pub const PARTIAL_ROUNDS: usize = 57;
    pub const ALPHA: u64 = 5;
    
    /// Export parameters as JSON for crypto/ crate
    pub fn export_json() -> String {
        serde_json::json!({
            "width": WIDTH,
            "rate": RATE,
            "capacity": CAPACITY,
            "full_rounds": FULL_ROUNDS,
            "partial_rounds": PARTIAL_ROUNDS,
            "alpha": ALPHA,
            "field": "BN254_Fr",
            "note": "Copy these parameters to crypto/src/poseidon.rs"
        }).to_string()
    }
}

/// Poseidon hasher for BN254
pub struct PoseidonHasher;

impl PoseidonHasher {
    /// Hash two field elements
    pub fn hash_two(left: Fr, right: Fr) -> Fr {
        Self::hash(&[left, right])
    }
    
    /// Hash arbitrary number of field elements
    pub fn hash(inputs: &[Fr]) -> Fr {
        // Initialize state
        let mut state = [Fr::from(0u64); params::WIDTH];
        
        // Absorb inputs (rate = 2 elements at a time)
        for chunk in inputs.chunks(params::RATE) {
            for (i, &input) in chunk.iter().enumerate() {
                state[i] += input;
            }
            state = Self::permute(state);
        }
        
        // Return first element as hash output
        state[0]
    }
    
    /// Poseidon permutation
    fn permute(mut state: [Fr; params::WIDTH]) -> [Fr; params::WIDTH] {
        let round_constants = Self::get_round_constants();
        let mds = Self::get_mds_matrix();
        
        let half_full = params::FULL_ROUNDS / 2;
        let mut rc_offset = 0;
        
        // First half of full rounds
        for _ in 0..half_full {
            // Add round constants
            for i in 0..params::WIDTH {
                state[i] += round_constants[rc_offset + i];
            }
            rc_offset += params::WIDTH;
            
            // S-box (x^5) on all elements
            for i in 0..params::WIDTH {
                state[i] = Self::sbox(state[i]);
            }
            
            // MDS matrix multiplication
            state = Self::mds_multiply(&state, &mds);
        }
        
        // Partial rounds
        for _ in 0..params::PARTIAL_ROUNDS {
            // Add round constants
            for i in 0..params::WIDTH {
                state[i] += round_constants[rc_offset + i];
            }
            rc_offset += params::WIDTH;
            
            // S-box only on first element
            state[0] = Self::sbox(state[0]);
            
            // MDS matrix multiplication
            state = Self::mds_multiply(&state, &mds);
        }
        
        // Second half of full rounds
        for _ in 0..half_full {
            // Add round constants
            for i in 0..params::WIDTH {
                state[i] += round_constants[rc_offset + i];
            }
            rc_offset += params::WIDTH;
            
            // S-box on all elements
            for i in 0..params::WIDTH {
                state[i] = Self::sbox(state[i]);
            }
            
            // MDS matrix multiplication
            state = Self::mds_multiply(&state, &mds);
        }
        
        state
    }
    
    /// S-box: x^5
    #[inline]
    fn sbox(x: Fr) -> Fr {
        let x2 = x * x;
        let x4 = x2 * x2;
        x4 * x
    }
    
    /// MDS matrix multiplication
    fn mds_multiply(state: &[Fr; params::WIDTH], mds: &[[Fr; params::WIDTH]; params::WIDTH]) -> [Fr; params::WIDTH] {
        let mut result = [Fr::from(0u64); params::WIDTH];
        for i in 0..params::WIDTH {
            for j in 0..params::WIDTH {
                result[i] += mds[i][j] * state[j];
            }
        }
        result
    }
    
    /// Get MDS matrix (Cauchy matrix construction)
    fn get_mds_matrix() -> [[Fr; params::WIDTH]; params::WIDTH] {
        // Using standard Cauchy matrix construction
        // M[i][j] = 1 / (x_i + y_j) where x and y are distinct elements
        let mut mds = [[Fr::from(0u64); params::WIDTH]; params::WIDTH];
        
        for i in 0..params::WIDTH {
            for j in 0..params::WIDTH {
                let x = Fr::from((i + 1) as u64);
                let y = Fr::from((j + params::WIDTH + 1) as u64);
                mds[i][j] = (x + y).inverse().unwrap();
            }
        }
        
        mds
    }
    
    /// Get round constants
    fn get_round_constants() -> Vec<Fr> {
        // Generate using Grain LFSR (deterministic)
        // For production, use the standard Poseidon constants
        let num_constants = params::WIDTH * (params::FULL_ROUNDS + params::PARTIAL_ROUNDS);
        let mut constants = Vec::with_capacity(num_constants);
        
        // Simplified constant generation (for demo)
        // In production, use proper Grain LFSR
        for i in 0..num_constants {
            let seed = format!("poseidon_bn254_{}_{}", params::WIDTH, i);
            let hash = blake2b_simd::blake2b(seed.as_bytes());
            let bytes: [u8; 32] = hash.as_bytes()[0..32].try_into().unwrap();
            constants.push(Fr::from_le_bytes_mod_order(&bytes));
        }
        
        constants
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::rand::rngs::OsRng;
    
    #[test]
    fn test_hash_deterministic() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);
        
        let h1 = PoseidonHasher::hash_two(a, b);
        let h2 = PoseidonHasher::hash_two(a, b);
        
        assert_eq!(h1, h2, "Hash should be deterministic");
    }
    
    #[test]
    fn test_hash_different_inputs() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);
        
        let h1 = PoseidonHasher::hash_two(a, b);
        let h2 = PoseidonHasher::hash_two(a, c);
        
        assert_ne!(h1, h2, "Different inputs should produce different hashes");
    }
    
    #[test]
    fn export_params_for_akshay() {
        let json = params::export_json();
        println!("=== POSEIDON PARAMETERS FOR AKSHAY ===");
        println!("{}", json);
        println!("======================================");
        println!("Copy these to crypto/src/poseidon.rs");
    }
}