//! Relay Node Implementation

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use std::collections::{VecDeque, HashSet};

use crate::sphinx::SphinxPacket;
use crate::MixnetError;

/// Message at a relay node
#[derive(Clone, Debug)]
pub struct RelayMessage {
    pub packet_id: [u8; 32],
    pub packet: SphinxPacket,
    pub received_at: u64,
    pub hop_count: u8,
}

impl RelayMessage {
    pub fn new(packet_id: [u8; 32], packet: SphinxPacket) -> Self {
        Self {
            packet_id,
            packet,
            received_at: 0, // Simplified for no_std
            hop_count: 0,
        }
    }
}

/// Relay node state
pub struct RelayNode {
    pub id: String,
    pub secret_key: [u8; 32],
    queue: VecDeque<RelayMessage>,
    processed: HashSet<[u8; 32]>,
}

impl RelayNode {
    pub fn new(id: String, secret_key: [u8; 32]) -> Self {
        Self {
            id,
            secret_key,
            queue: VecDeque::new(),
            processed: HashSet::new(),
        }
    }

    pub fn receive_packet(
    &mut self,
    packet: SphinxPacket,
) -> Result<(), MixnetError> {
    let mut packet_id = [0u8; 32];
    packet_id.copy_from_slice(&packet.header.ephemeral_key[..32]);

    if self.processed.contains(&packet_id) {
        return Err(MixnetError::InvalidPacket(
            String::from("Packet already processed"),
        ));
    }

    let message = RelayMessage::new(packet_id, packet);
    self.queue.push_back(message);

    Ok(())
    }

    pub fn process_next_packet(&mut self) -> Result<Option<SphinxPacket>, MixnetError> {
        if let Some(mut message) = self.queue.pop_front() {
            let next_packet = message.packet.peel_layer(&self.secret_key)?;
            self.processed.insert(message.packet_id);
            message.hop_count += 1;
            Ok(Some(next_packet))
        } else {
            Ok(None)
        }
    }

    pub fn process_all_packets(&mut self) -> Result<Vec<SphinxPacket>, MixnetError> {
        let mut output = Vec::new();

        while let Some(packet) = self.process_next_packet()? {
            output.push(packet);
        }

        Ok(output)
    }

    pub fn queue_size(&self) -> usize {
        self.queue.len()
    }

    pub fn processed_count(&self) -> usize {
        self.processed.len()
    }

    pub fn clear_processed(&mut self) {
        self.processed.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc::string::ToString;
    use crate::sphinx::RelayHop;

    #[test]
    fn test_relay_node_creation() {
        let relay = RelayNode::new("relay1".to_string(), [1u8; 32]);
        assert_eq!(relay.id, "relay1");
        assert_eq!(relay.queue_size(), 0);
    }
}