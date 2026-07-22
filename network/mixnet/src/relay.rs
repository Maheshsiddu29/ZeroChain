//! Relay Node Implementation
//!
//! A relay node receives Sphinx packets, peels one encryption layer,
//! and forwards to the next relay or destination

use crate::sphinx::SphinxPacket;
use crate::MixnetError;
use std::collections::VecDeque;

/// Message at a relay node
#[derive(Clone, Debug)]
pub struct RelayMessage {
    /// Original packet ID
    pub packet_id: [u8; 32],
    /// Current packet state
    pub packet: SphinxPacket,
    /// Received timestamp
    pub received_at: u64,
    /// Number of times processed
    pub hop_count: u8,
}

impl RelayMessage {
    pub fn new(packet_id: [u8; 32], packet: SphinxPacket) -> Self {
        Self {
            packet_id,
            packet,
            received_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            hop_count: 0,
        }
    }
}

/// Relay node state
pub struct RelayNode {
    /// Relay node ID
    pub id: String,
    /// Private key (secret)
    pub secret_key: [u8; 32],
    /// Message queue
    queue: VecDeque<RelayMessage>,
    /// Processed packet IDs (for deduplication)
    processed: std::collections::HashSet<[u8; 32]>,
}

impl RelayNode {
    /// Create new relay node
    pub fn new(id: String, secret_key: [u8; 32]) -> Self {
        Self {
            id,
            secret_key,
            queue: VecDeque::new(),
            processed: std::collections::HashSet::new(),
        }
    }

    /// Receive packet at relay
    pub fn receive_packet(
        &mut self,
        packet: SphinxPacket,
    ) -> Result<(), MixnetError> {
        // Generate packet ID
        let mut packet_id = [0u8; 32];
        packet_id.copy_from_slice(&packet.header.ephemeral_key[..32]);

        // Check for duplicate — mark seen immediately so a second receive of
        // the same packet is rejected even while it's still queued.
        if !self.processed.insert(packet_id) {
            return Err(MixnetError::InvalidPacket(
                "Packet already processed".to_string(),
            ));
        }

        let message = RelayMessage::new(packet_id, packet);
        self.queue.push_back(message);

        Ok(())
    }

    /// Process next packet in queue
    /// Returns the packet to forward (with one layer peeled)
    pub fn process_next_packet(&mut self) -> Result<Option<SphinxPacket>, MixnetError> {
        if let Some(mut message) = self.queue.pop_front() {
            // Peel onion layer
            let next_packet = message.packet.peel_layer(&self.secret_key)?;
            message.hop_count += 1;
            Ok(Some(next_packet))
        } else {
            Ok(None)
        }
    }

    /// Process all queued packets
    pub fn process_all_packets(&mut self) -> Result<Vec<SphinxPacket>, MixnetError> {
        let mut output = Vec::new();

        while let Some(packet) = self.process_next_packet()? {
            output.push(packet);
        }

        Ok(output)
    }

    /// Get queue size
    pub fn queue_size(&self) -> usize {
        self.queue.len()
    }

    /// Get number of processed packets
    pub fn processed_count(&self) -> usize {
        self.processed.len()
    }

    /// Clear old processed records (for cleanup)
    pub fn clear_processed(&mut self) {
        self.processed.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sphinx::RelayHop;

    #[test]
    fn test_relay_node_creation() {
        let relay = RelayNode::new("relay1".to_string(), [1u8; 32]);
        assert_eq!(relay.id, "relay1");
        assert_eq!(relay.queue_size(), 0);
    }

    #[test]
    fn test_packet_queueing() {
        let mut relay = RelayNode::new("relay1".to_string(), [1u8; 32]);

        let message = b"test";
        let path = vec![RelayHop::new(b"relay1".to_vec(), [1u8; 32])];
        let packet = SphinxPacket::create(message, &path, 512).unwrap();

        assert!(relay.receive_packet(packet).is_ok());
        assert_eq!(relay.queue_size(), 1);
    }

    #[test]
    fn test_duplicate_packet_rejected() {
        let mut relay = RelayNode::new("relay1".to_string(), [1u8; 32]);

        let message = b"test";
        let path = vec![RelayHop::new(b"relay1".to_vec(), [1u8; 32])];
        let packet = SphinxPacket::create(message, &path, 512).unwrap();

        assert!(relay.receive_packet(packet.clone()).is_ok());
        assert!(relay.receive_packet(packet).is_err());
    }
}