//! Fluff phase implementation
//!
//! Handles normal broadcast to all peers

use std::collections::HashSet;

/// Tracks peers that have already seen a transaction
#[derive(Clone, Debug)]
pub struct FluffPhaseTracker {
    /// Set of peer IDs that received this transaction
    seen_by: HashSet<Vec<u8>>,
}

impl FluffPhaseTracker {
    pub fn new() -> Self {
        Self {
            seen_by: HashSet::new(),
        }
    }

    pub fn mark_sent(&mut self, peer: Vec<u8>) {
        self.seen_by.insert(peer);
    }

    pub fn has_seen(&self, peer: &[u8]) -> bool {
        self.seen_by.contains(peer)
    }

    pub fn peer_count(&self) -> usize {
        self.seen_by.len()
    }
}

impl Default for FluffPhaseTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fluff_tracking() {
        let mut tracker = FluffPhaseTracker::new();
        let peer1 = vec![1, 2, 3];
        let peer2 = vec![4, 5, 6];

        assert!(!tracker.has_seen(&peer1));
        tracker.mark_sent(peer1.clone());
        assert!(tracker.has_seen(&peer1));
        assert!(!tracker.has_seen(&peer2));

        tracker.mark_sent(peer2.clone());
        assert_eq!(tracker.peer_count(), 2);
    }
}