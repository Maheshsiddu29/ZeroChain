//! Mixnet Module for ZeroChain
//!
//! Provides anonymous message routing via Sphinx packets and onion encryption.
//! Each relay peels one encryption layer and forwards to next relay.
//!
//! Architecture:
//! ```
//! Sender → [Relay 1] → [Relay 2] → [Relay 3] → Recipient
//!           (peel)       (peel)       (peel)
//! ```


pub mod sphinx;
pub mod onion;
pub mod topology;
pub mod relay;

pub use sphinx::{SphinxPacket, SphinxError};
pub use onion::{OnionEncryption, OnionError};
pub use topology::{Topology, RelayConfig, TopologyBuilder};
pub use relay::{RelayNode, RelayMessage};

#[cfg(test)]
mod tests;

/// Mixnet configuration
#[derive(Clone, Debug)]
pub struct MixnetConfig {
    /// Number of relay hops (typically 3)
    pub num_hops: usize,
    /// Packet size in bytes (fixed for uniformity)
    pub packet_size: usize,
    /// Relay topology
    pub topology: Topology,
    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for MixnetConfig {
    fn default() -> Self {
        Self {
            num_hops: 3,
            packet_size: 1024,
            topology: Topology::default(),
            verbose: false,
        }
    }
}

/// Mixnet error types
#[derive(Clone, Debug)]
pub enum MixnetError {
    /// Invalid packet format
    InvalidPacket(String),
    /// Encryption/decryption failed
    CryptoError(String),
    /// Relay not found in topology
    RelayNotFound(String),
    /// Invalid topology
    InvalidTopology(String),
    /// Packet too large
    PacketTooLarge,
    /// Onion encryption error
    OnionError(String),
}

impl std::fmt::Display for MixnetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPacket(msg) => write!(f, "Invalid packet: {}", msg),
            Self::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            Self::RelayNotFound(id) => write!(f, "Relay not found: {}", id),
            Self::InvalidTopology(msg) => write!(f, "Invalid topology: {}", msg),
            Self::PacketTooLarge => write!(f, "Packet exceeds maximum size"),
            Self::OnionError(msg) => write!(f, "Onion error: {}", msg),
        }
    }
}

impl From<crate::sphinx::SphinxError> for MixnetError {
    fn from(e: crate::sphinx::SphinxError) -> Self {
        MixnetError::CryptoError(e.to_string())
    }
}

impl std::error::Error for MixnetError {}

/// Convert message to anonymized Sphinx packet
pub fn create_message_packet(
    message: &[u8],
    recipient_id: &str,
    topology: &Topology,
    config: &MixnetConfig,
) -> Result<SphinxPacket, MixnetError> {
    // Get relay path to recipient
    let path = topology.get_path_to(recipient_id, config.num_hops)?;

    // Create Sphinx packet through relay chain
    SphinxPacket::create(message, &path, config.packet_size).map_err(Into::into)
}

/// Process incoming packet at relay node
pub fn process_packet_at_relay(
    packet: &SphinxPacket,
    relay_secret: &[u8; 32],
) -> Result<SphinxPacket, MixnetError> {
    // Peel onion layer and get next relay
    let next_packet = packet.peel_layer(relay_secret)?;
    Ok(next_packet)
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_message_flow_through_mixnet() {
        // TODO: Integration test
    }
}