//! Adapter: Dandelion++ core → sc-network integration
//!
//! Bridges pure protocol logic with substrate networking layer

use network_dandelion::{DandelionCore, DandelionConfig, DandelionDecision};
use std::sync::Arc;
use parking_lot::Mutex;
use std::time::Duration;

/// Transaction routing decision
#[derive(Clone, Debug, PartialEq)]
pub enum TransactionRouting {
    /// Send to specific peer in stem phase
    StemToSinglePeer(Vec<u8>),
    /// Broadcast to all connected peers
    BroadcastToAll,
}

/// Wrapper around DandelionCore for sc-network integration
pub struct DandelionAdapter {
    core: Arc<Mutex<DandelionCore>>,
}

impl DandelionAdapter {
    /// Create new adapter with stem hop count
    pub fn new(stem_hops: u32) -> Self {
        let config = DandelionConfig {
            stem_hops,
            safety_timeout: Duration::from_secs(30),
            stem_probability: 0.6,
        };

        Self {
            core: Arc::new(Mutex::new(DandelionCore::new(config))),
        }
    }

    /// Process transaction before broadcast
    pub fn process_transaction(
        &self,
        tx_hash: Vec<u8>,
        available_peers: &[Vec<u8>],
    ) -> TransactionRouting {
        let mut core = self.core.lock();

        match core.process_tx(tx_hash, available_peers) {
            DandelionDecision::Stem(peer) => TransactionRouting::StemToSinglePeer(peer),
            DandelionDecision::Fluff => TransactionRouting::BroadcastToAll,
        }
    }

    /// Advance stem phase when peer relays transaction
    pub fn on_transaction_relayed(
        &self,
        tx_hash: Vec<u8>,
        available_peers: &[Vec<u8>],
    ) -> TransactionRouting {
        let mut core = self.core.lock();

        match core.advance_stem(&tx_hash, available_peers) {
            DandelionDecision::Stem(next_peer) => {
                TransactionRouting::StemToSinglePeer(next_peer)
            }
            DandelionDecision::Fluff => TransactionRouting::BroadcastToAll,
        }
    }

    /// Check if transaction is in stem phase
    pub fn is_in_stem(&self, tx_hash: &[u8]) -> bool {
        self.core.lock().is_in_stem(tx_hash)
    }

    /// Get stem phase hop count
    pub fn get_hop_count(&self, tx_hash: &[u8]) -> Option<u32> {
        self.core.lock().get_hop_count(tx_hash)
    }

    /// Cleanup expired transactions
    pub fn cleanup_expired(&self) {
        self.core.lock().cleanup_expired();
    }

    /// Force transaction to fluff (for testing)
    pub fn force_fluff(&self, tx_hash: &[u8]) {
        self.core.lock().force_fluff(tx_hash);
    }

    /// Get number of transactions in stem phase
    pub fn stem_count(&self) -> usize {
        self.core.lock().stem_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_creation() {
        let adapter = DandelionAdapter::new(4);
        let tx_hash = vec![1, 2, 3];
        let peers = vec![vec![10], vec![20]];
        
        let _routing = adapter.process_transaction(tx_hash, &peers);
        // Test passes if no panic
    }

    #[test]
    fn test_stem_tracking() {
        let adapter = DandelionAdapter::new(4);
        let tx_hash = vec![1, 2, 3];
        let peers = vec![vec![10], vec![20], vec![30]];

        // Try multiple times due to randomness
        for _ in 0..20 {
            let routing = adapter.process_transaction(tx_hash.clone(), &peers);
            if matches!(routing, TransactionRouting::StemToSinglePeer(_)) {
                assert!(adapter.is_in_stem(&tx_hash));
                return; // Test passed
            }
        }
    }
}