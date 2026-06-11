//! Mixnet Module for ZeroChain

#![no_std]

extern crate alloc;
extern crate std;

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use std::collections::HashMap;

pub mod sphinx;
pub mod onion;
pub mod topology;
pub mod relay;

pub use sphinx::{SphinxPacket, SphinxError};
pub use onion::{OnionEncryption, OnionError};
pub use topology::{Topology, RelayConfig, TopologyBuilder};
pub use relay::{RelayNode, RelayMessage};

/// Mixnet configuration
#[derive(Clone, Debug)]
pub struct MixnetConfig {
    pub num_hops: usize,
    pub packet_size: usize,
    pub topology: Topology,
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
    InvalidPacket(String),
    CryptoError(String),
    RelayNotFound(String),
    InvalidTopology(String),
    PacketTooLarge,
    OnionError(String),
}

impl core::fmt::Display for MixnetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

// Convert SphinxError to MixnetError
impl From<sphinx::SphinxError> for MixnetError {
    fn from(err: sphinx::SphinxError) -> Self {
        Self::CryptoError(alloc::format!("{:?}", err))
    }
}

// Convert OnionError to MixnetError
impl From<onion::OnionError> for MixnetError {
    fn from(err: onion::OnionError) -> Self {
        Self::OnionError(alloc::format!("{:?}", err))
    }
}

/// Convert message to anonymized Sphinx packet
pub fn create_message_packet(
    message: &[u8],
    recipient_id: &str,
    topology: &Topology,
    config: &MixnetConfig,
) -> Result<SphinxPacket, MixnetError> {
    let path = topology.get_path_to(recipient_id, config.num_hops)?;
    SphinxPacket::create(message, &path, config.packet_size).map_err(MixnetError::from)
}

/// Process incoming packet at relay node
pub fn process_packet_at_relay(
    packet: &SphinxPacket,
    relay_secret: &[u8; 32],
) -> Result<SphinxPacket, MixnetError> {
    packet.peel_layer(relay_secret).map_err(MixnetError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(3, 3);
    }
}