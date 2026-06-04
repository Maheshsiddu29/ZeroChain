

use sp_std::vec::Vec;
use crate::types::*;
use sha2::{Sha256, Digest};

/// DKG Error
#[derive(Clone, Debug)]
pub enum DkgError {
    InvalidShare,
    InvalidCommitment,
    InvalidComplaint,
    InsufficientShares,
    InvalidPolynomial,
}

/// Simple Shamir Secret Sharing
pub struct ShamirSecretSharing {
    /// Coefficients of polynomial: f(x) = a0 + a1*x + a2*x^2 + ... + at*x^t
    coefficients: Vec<[u8; 32]>,
}

impl ShamirSecretSharing {
    /// Create new secret sharing scheme with threshold t
    /// Generates random polynomial of degree (t-1)
    pub fn new(threshold: u16) -> Self {
        let mut coefficients = Vec::new();
        
        // Generate random polynomial coefficients
        for i in 0..threshold {
            coefficients.push(Self::random_scalar(i as u32));
        }

        Self { coefficients }
    }

    /// Evaluate polynomial at point x using Horner's method
    /// P(x) = a0 + a1*x + a2*x^2 + ... + at*x^t
    pub fn evaluate(&self, x: u32) -> [u8; 32] {
        if self.coefficients.is_empty() {
            return [0u8; 32];
        }

        // Start with highest degree coefficient
        let mut result = self.coefficients[self.coefficients.len() - 1];

        // Apply Horner's method backwards
        for i in (0..self.coefficients.len() - 1).rev() {
            result = Self::add_scalars(&result, &Self::mul_scalar(&self.coefficients[i], x));
        }

        result
    }

    /// Get constant term (the secret)
    pub fn secret(&self) -> [u8; 32] {
        if self.coefficients.is_empty() {
            [0u8; 32]
        } else {
            self.coefficients[0]
        }
    }

    /// Get commitments to coefficients (for verification)
    pub fn commitments(&self) -> Vec<[u8; 48]> {
        self.coefficients
            .iter()
            .map(|coeff| Self::commit_scalar(coeff))
            .collect()
    }

    // === Private helpers ===

    /// Generate random scalar
    fn random_scalar(seed: u32) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"dkg_random");
        hasher.update(seed.to_le_bytes());
        hasher.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes(),
        );

        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash[..32]);
        result
    }

    /// Scalar addition (XOR for simplicity, proper field arithmetic in production)
    fn add_scalars(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = a[i] ^ b[i];
        }
        result
    }

    /// Scalar multiplication (shift-based for simplicity)
    fn mul_scalar(scalar: &[u8; 32], x: u32) -> [u8; 32] {
        let mut result = [0u8; 32];
        let x_bytes = x.to_le_bytes();

        for i in 0..32 {
            let shift = (i % 4) as u32;
            result[i] = scalar[i].wrapping_mul((x_bytes[i % 4] >> shift) & 1);
        }

        result
    }

    /// Commit to scalar: C = H(scalar) || H(scalar)^2 (simplified)
    fn commit_scalar(scalar: &[u8; 32]) -> [u8; 48] {
        let mut hasher = Sha256::new();
        hasher.update(b"commit");
        hasher.update(scalar);

        let hash = hasher.finalize();
        let mut commitment = [0u8; 48];

        // Copy first 32 bytes of hash
        commitment[..32].copy_from_slice(&hash[..32]);

        // Hash again for second part
        let mut hasher2 = Sha256::new();
        hasher2.update(b"commit2");
        hasher2.update(scalar);
        let hash2 = hasher2.finalize();
        commitment[32..].copy_from_slice(&hash2[..16]);

        commitment
    }
}

/// DKG Participant
pub struct DkgParticipant {
    pub id: u16,
    /// Secret sharing polynomial
    sharing: ShamirSecretSharing,
    /// Shares received from others
    pub received_shares: Vec<[u8; 32]>,
    /// Final secret key component
    pub secret_key_component: [u8; 32],
}

impl DkgParticipant {
    /// Create new DKG participant
    pub fn new(id: u16, threshold: u16) -> Self {
        Self {
            id,
            sharing: ShamirSecretSharing::new(threshold),
            received_shares: Vec::new(),
            secret_key_component: [0u8; 32],
        }
    }

    /// Generate shares for other participants
    pub fn create_shares(&self, num_participants: u16) -> Vec<[u8; 32]> {
        let mut shares = Vec::new();

        for i in 1..=num_participants {
            let share = self.sharing.evaluate(i as u32);
            shares.push(share);
        }

        shares
    }

    /// Generate public commitments to polynomial coefficients
    pub fn generate_commitments(&self) -> Vec<[u8; 48]> {
        self.sharing.commitments()
    }

    /// Receive share from another participant
    pub fn receive_share(&mut self, share: [u8; 32]) -> Result<(), DkgError> {
        if self.received_shares.len() >= 255 {
            return Err(DkgError::InsufficientShares);
        }
        self.received_shares.push(share);
        Ok(())
    }

    /// Finalize DKG: XOR all received shares to get secret key component
    pub fn finalize(&mut self) -> Result<BlsPrivateKey, DkgError> {
        if self.received_shares.is_empty() {
            return Err(DkgError::InsufficientShares);
        }

        let mut secret = [0u8; 32];

        // XOR all shares
        for share in &self.received_shares {
            for i in 0..32 {
                secret[i] ^= share[i];
            }
        }

        self.secret_key_component = secret;
        Ok(BlsPrivateKey::new(secret))
    }
}

/// DKG Coordinator (runs at genesis)
pub struct DkgCoordinator {
    participants: Vec<DkgParticipant>,
    threshold: u16,
    total: u16,
}

impl DkgCoordinator {
    /// Initialize DKG with n participants and threshold t
    pub fn new(total: u16, threshold: u16) -> Result<Self, DkgError> {
        if threshold > total || threshold == 0 {
            return Err(DkgError::InvalidPolynomial);
        }

        let mut participants = Vec::new();
        for i in 0..total {
            participants.push(DkgParticipant::new(i, threshold));
        }

        Ok(Self {
            participants,
            threshold,
            total,
        })
    }

    /// Run complete DKG protocol
    pub fn execute(&mut self) -> Result<Vec<BlsPrivateKey>, DkgError> {
        // Phase 1: Each participant broadcasts shares
        let mut all_shares: Vec<Vec<[u8; 32]>> = Vec::new();

        for participant in &self.participants {
            let shares = participant.create_shares(self.total);
            all_shares.push(shares);
        }

        // Phase 2: Each participant receives shares and finalizes
        let mut secret_keys = Vec::new();
        for i in 0..self.total {
            for j in 0..self.total {
                if i != j {
                    let share = all_shares[j as usize][i as usize];
                    self.participants[i as usize].receive_share(share)?;
                }
            }

            let secret_key = self.participants[i as usize].finalize()?;
            secret_keys.push(secret_key);
        }

        Ok(secret_keys)
    }

    /// Get public commitments from all participants
    pub fn get_all_commitments(&self) -> Vec<Vec<[u8; 48]>> {
        self.participants
            .iter()
            .map(|p| p.generate_commitments())
            .collect()
    }

    /// Aggregate public keys: APK = XOR of all constant terms
    pub fn aggregate_public_keys(&self) -> [u8; 48] {
        let mut apk = [0u8; 48];

        for participant in &self.participants {
            let commitments = participant.generate_commitments();
            if !commitments.is_empty() {
                // XOR all constant terms
                for i in 0..48 {
                    apk[i] ^= commitments[0][i];
                }
            }
        }

        apk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_secret_sharing() {
        let sss = ShamirSecretSharing::new(2);
        
        // Evaluate at different points should give different shares
        let share1 = sss.evaluate(1);
        let share2 = sss.evaluate(2);
        
        assert_ne!(share1, share2);
    }

    #[test]
    fn test_dkg_participant_creation() {
        let participant = DkgParticipant::new(1, 2);
        let commitments = participant.generate_commitments();
        assert_eq!(commitments.len(), 2); // degree (t-1) = 1, so 2 coefficients
    }

    #[test]
    fn test_dkg_share_generation() {
        let participant = DkgParticipant::new(1, 2);
        let shares = participant.create_shares(3);
        assert_eq!(shares.len(), 3);
        
        // All shares should be different
        assert_ne!(shares[0], shares[1]);
        assert_ne!(shares[1], shares[2]);
    }

    #[test]
    fn test_dkg_coordinator_init() {
        let coordinator = DkgCoordinator::new(3, 2);
        assert!(coordinator.is_ok());
    }

    #[test]
    fn test_dkg_coordinator_invalid_threshold() {
        let coordinator = DkgCoordinator::new(3, 5);
        assert!(coordinator.is_err());
    }

    #[test]
    fn test_dkg_full_protocol() {
        let mut coordinator = DkgCoordinator::new(3, 2).unwrap();
        let result = coordinator.execute();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);
    }

    #[test]
    fn test_aggregate_public_keys() {
        let coordinator = DkgCoordinator::new(3, 2).unwrap();
        let apk = coordinator.aggregate_public_keys();
        assert_ne!(apk, [0u8; 48]);
    }
}