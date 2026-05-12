//! Pure Dandelion++ privacy protocol
//! Network-agnostic: stem phase, fluff phase, safety timeout
//!
//! No dependencies on sc-network or substrate - fully testable in isolation

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Configuration for Dandelion++ protocol
#[derive(Clone, Debug)]
pub struct DandelionConfig {
    /// Number of hops in stem phase (2-4, randomized)
    pub stem_hops: u32,
    /// Timeout to switch to fluff if stem node dies
    pub safety_timeout: Duration,
    /// Probability of entering stem phase (0.0-1.0, typically 0.6)
    pub stem_probability: f32,
}

impl Default for DandelionConfig {
    fn default() -> Self {
        Self {
            stem_hops: 4,
            safety_timeout: Duration::from_secs(30),
            stem_probability: 0.6,
        }
    }
}

/// State of a transaction in stem phase
#[derive(Clone, Debug)]
struct StemState {
    /// Current hop number (0 to stem_hops)
    hop_count: u32,
    /// When this transaction entered stem phase
    started_at: Instant,
    /// Last peer it was sent to
    last_peer: Vec<u8>,
}

/// Decision from Dandelion protocol
#[derive(Clone, Debug, PartialEq)]
pub enum DandelionDecision {
    /// Send to single peer in stem phase
    Stem(Vec<u8>),
    /// Broadcast to all connected peers (fluff phase)
    Fluff,
}

/// Core Dandelion++ protocol engine
pub struct DandelionCore {
    config: DandelionConfig,
    /// Map: transaction_hash -> stem_state
    stem_transactions: HashMap<Vec<u8>, StemState>,
}

impl DandelionCore {
    /// Create new Dandelion++ instance
    pub fn new(config: DandelionConfig) -> Self {
        Self {
            config,
            stem_transactions: HashMap::new(),
        }
    }

    /// Process outgoing transaction: decide stem or fluff
    ///
    /// # Arguments
    /// * `tx_hash` - Unique transaction identifier
    /// * `available_peers` - List of connected peer addresses
    ///
    /// # Returns
    /// `Stem(peer)` → send to single peer  
    /// `Fluff` → broadcast to all peers
    pub fn process_tx(
        &mut self,
        tx_hash: Vec<u8>,
        available_peers: &[Vec<u8>],
    ) -> DandelionDecision {
        // If no peers, must broadcast immediately
        if available_peers.is_empty() {
            return DandelionDecision::Fluff;
        }

        // Random decision: stem or fluff
        if self.decide_stem() {
            // Enter stem phase: select random peer
            let peer = self.select_random_peer(available_peers);
            self.stem_transactions.insert(
                tx_hash.clone(),
                StemState {
                    hop_count: 0,
                    started_at: Instant::now(),
                    last_peer: peer.clone(),
                },
            );
            DandelionDecision::Stem(peer)
        } else {
            // Enter fluff phase immediately
            DandelionDecision::Fluff
        }
    }

  /// Advance stem phase when peer relays transaction
///
/// Call this when the stem peer forwards the transaction.
/// - If hop limit reached → switch to fluff
/// - If timeout exceeded → switch to fluff  
/// - Otherwise → forward to next random peer
pub fn advance_stem(
    &mut self,
    tx_hash: &[u8],
    available_peers: &[Vec<u8>],
) -> DandelionDecision {
    // Check if transaction exists and get current state
    let should_advance = if let Some(state) = self.stem_transactions.get(tx_hash) {
        // Check safety timeout
        if state.started_at.elapsed() > self.config.safety_timeout {
            false // Timeout exceeded
        } else {
            true // Can advance
        }
    } else {
        // Unknown transaction
        return DandelionDecision::Fluff;
    };

    // Handle timeout
    if !should_advance {
        self.stem_transactions.remove(tx_hash);
        return DandelionDecision::Fluff;
    }

    // Check if we have peers available
    if available_peers.is_empty() {
        self.stem_transactions.remove(tx_hash);
        return DandelionDecision::Fluff;
    }

    // Select next peer before modifying state
    let next_peer = self.select_random_peer(available_peers);
    
    // Update state and check hop limit
    if let Some(state) = self.stem_transactions.get_mut(tx_hash) {
        state.hop_count += 1; // Increment FIRST
        
        // Check if we've reached the limit AFTER incrementing
        if state.hop_count >= self.config.stem_hops {
            self.stem_transactions.remove(tx_hash);
            return DandelionDecision::Fluff;
        }
        
        state.last_peer = next_peer.clone();
    }

    DandelionDecision::Stem(next_peer)
} 

    /// Check if transaction is in stem phase
    pub fn is_in_stem(&self, tx_hash: &[u8]) -> bool {
        self.stem_transactions.contains_key(tx_hash)
    }

    /// Check if transaction should broadcast (fluff phase)
    pub fn should_broadcast(&self, tx_hash: &[u8]) -> bool {
        !self.is_in_stem(tx_hash)
    }

    /// Get current hop count for transaction
    pub fn get_hop_count(&self, tx_hash: &[u8]) -> Option<u32> {
        self.stem_transactions.get(tx_hash).map(|s| s.hop_count)
    }

    /// Force transaction to fluff phase (for testing/debugging)
    pub fn force_fluff(&mut self, tx_hash: &[u8]) {
        self.stem_transactions.remove(tx_hash);
    }

    /// Decide whether to enter stem phase
    fn decide_stem(&self) -> bool {
        // Use current time as seed for pseudo-random decision
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        
        let random_value = (nanos as f32) / (1_000_000_000.0_f32);
        random_value < self.config.stem_probability
    }

    /// Select random peer from available list
    fn select_random_peer(&self, peers: &[Vec<u8>]) -> Vec<u8> {
        // Use current time nanoseconds as seed
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        
        let idx = (nanos as usize) % peers.len();
        peers[idx].clone()
    }

    /// Get number of transactions in stem phase (for metrics)
    pub fn stem_count(&self) -> usize {
        self.stem_transactions.len()
    }

    /// Cleanup expired transactions (call periodically)
    pub fn cleanup_expired(&mut self) {
        self.stem_transactions.retain(|_, state| {
            state.started_at.elapsed() <= self.config.safety_timeout
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stem_phase_creation() {
        let config = DandelionConfig::default();
        let mut dandelion = DandelionCore::new(config);

        let tx_hash = vec![1, 2, 3];
        let peers = vec![vec![10], vec![20], vec![30]];

        // Try multiple times to get stem (due to randomness)
        let mut got_stem = false;
        for _ in 0..20 {
            dandelion.stem_transactions.clear();
            let decision = dandelion.process_tx(tx_hash.clone(), &peers);
            if matches!(decision, DandelionDecision::Stem(_)) {
                got_stem = true;
                break;
            }
        }
        
        if got_stem {
            assert!(dandelion.is_in_stem(&tx_hash));
            assert!(!dandelion.should_broadcast(&tx_hash));
        }
    }

    #[test]
    fn test_fluff_phase_creation() {
        let mut config = DandelionConfig::default();
        config.stem_probability = 0.0; // Force fluff

        let mut dandelion = DandelionCore::new(config);
        let tx_hash = vec![1, 2, 3];
        let peers = vec![vec![10], vec![20], vec![30]];

        let decision = dandelion.process_tx(tx_hash.clone(), &peers);
        assert_eq!(decision, DandelionDecision::Fluff);
        assert!(!dandelion.is_in_stem(&tx_hash));
        assert!(dandelion.should_broadcast(&tx_hash));
    }

    #[test]
    fn test_stem_hop_advancement() {
        let config = DandelionConfig {
            stem_hops: 4,
            safety_timeout: Duration::from_secs(30),
            stem_probability: 1.0, // Always stem
        };
        let mut dandelion = DandelionCore::new(config);

        let tx_hash = vec![1, 2, 3];
        let peers = vec![vec![10], vec![20], vec![30]];

        // Start stem phase
        dandelion.process_tx(tx_hash.clone(), &peers);
        assert_eq!(dandelion.get_hop_count(&tx_hash), Some(0));

        // Advance hop
        dandelion.advance_stem(&tx_hash, &peers);
        assert_eq!(dandelion.get_hop_count(&tx_hash), Some(1));

        // Advance again
        dandelion.advance_stem(&tx_hash, &peers);
        assert_eq!(dandelion.get_hop_count(&tx_hash), Some(2));
    }

    #[test]
    fn test_stem_hop_limit() {
        let config = DandelionConfig {
            stem_hops: 2,
            safety_timeout: Duration::from_secs(30),
            stem_probability: 1.0,
        };
        let mut dandelion = DandelionCore::new(config);

        let tx_hash = vec![1, 2, 3];
        let peers = vec![vec![10], vec![20], vec![30]];

        // Start stem
        dandelion.process_tx(tx_hash.clone(), &peers);
        assert!(dandelion.is_in_stem(&tx_hash));

        // Hop 1
        dandelion.advance_stem(&tx_hash, &peers);
        assert!(dandelion.is_in_stem(&tx_hash));

        // Hop 2 - should hit limit and switch to fluff
        let decision = dandelion.advance_stem(&tx_hash, &peers);
        assert_eq!(decision, DandelionDecision::Fluff);
        assert!(!dandelion.is_in_stem(&tx_hash));
    }

    #[test]
    fn test_safety_timeout() {
        let config = DandelionConfig {
            stem_hops: 100, // High limit so timeout triggers first
            safety_timeout: Duration::from_millis(100),
            stem_probability: 1.0,
        };
        let mut dandelion = DandelionCore::new(config);

        let tx_hash = vec![1, 2, 3];
        let peers = vec![vec![10], vec![20], vec![30]];

        // Manually insert old state
        dandelion.stem_transactions.insert(
            tx_hash.clone(),
            StemState {
                hop_count: 0,
                started_at: Instant::now() - Duration::from_secs(1),
                last_peer: vec![10],
            },
        );

        // Advancing should trigger timeout
        let decision = dandelion.advance_stem(&tx_hash, &peers);
        assert_eq!(decision, DandelionDecision::Fluff);
        assert!(!dandelion.is_in_stem(&tx_hash));
    }

    #[test]
    fn test_no_peers_forces_fluff() {
        let config = DandelionConfig::default();
        let mut dandelion = DandelionCore::new(config);

        let tx_hash = vec![1, 2, 3];
        let empty_peers: Vec<Vec<u8>> = vec![];

        let decision = dandelion.process_tx(tx_hash.clone(), &empty_peers);
        assert_eq!(decision, DandelionDecision::Fluff);
    }

    #[test]
    fn test_cleanup_expired() {
        let config = DandelionConfig {
            stem_hops: 100,
            safety_timeout: Duration::from_millis(100),
            stem_probability: 1.0,
        };
        let mut dandelion = DandelionCore::new(config);

        let peers = vec![vec![10], vec![20]];

        // Create 3 transactions
        dandelion.process_tx(vec![1], &peers);
        dandelion.process_tx(vec![2], &peers);
        dandelion.process_tx(vec![3], &peers);
        assert_eq!(dandelion.stem_count(), 3);

        // Make one old
        dandelion.stem_transactions.get_mut(&vec![1]).unwrap().started_at =
            Instant::now() - Duration::from_secs(1);

        // Cleanup should remove expired
        dandelion.cleanup_expired();
        assert_eq!(dandelion.stem_count(), 2);
        assert!(!dandelion.is_in_stem(&vec![1]));
    }

    #[test]
    fn test_force_fluff() {
        let mut config = DandelionConfig::default();
        config.stem_probability = 1.0;

        let mut dandelion = DandelionCore::new(config);
        let tx_hash = vec![1, 2, 3];
        let peers = vec![vec![10], vec![20]];

        dandelion.process_tx(tx_hash.clone(), &peers);
        assert!(dandelion.is_in_stem(&tx_hash));

        dandelion.force_fluff(&tx_hash);
        assert!(!dandelion.is_in_stem(&tx_hash));
        assert!(dandelion.should_broadcast(&tx_hash));
    }
}