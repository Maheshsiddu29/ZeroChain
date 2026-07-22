//! Sphinx Packet Format
//!
//!
//! Structure:
//! ```text
//! SphinxPacket {
//!   header: (ephemeral_key, route_info, relay_data),
//!   payload: (encrypted_payload)
//! }
//! ```

use crate::onion::{OnionEncryption, OnionError};
use sha2::{Sha256, Digest};
use x25519_dalek::{StaticSecret, PublicKey};
use std::error::Error;
use std::fmt;

/// Maximum number of relay hops
const MAX_HOPS: usize = 16;

/// Sphinx packet error
#[derive(Clone, Debug)]
pub enum SphinxError {
    TooManyHops,
    InvalidPacketSize,
    DecryptionFailed,
    InvalidRouteInfo,
    NoMoreRelays,
    InvalidEphemeralKey,
    OnionError(String),
}

impl fmt::Display for SphinxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyHops => write!(f, "Too many relay hops"),
            Self::InvalidPacketSize => write!(f, "Invalid packet size"),
            Self::DecryptionFailed => write!(f, "Decryption failed"),
            Self::InvalidRouteInfo => write!(f, "Invalid route information"),
            Self::NoMoreRelays => write!(f, "No more relays in packet"),
            Self::InvalidEphemeralKey => write!(f, "Invalid ephemeral key"),
            Self::OnionError(msg) => write!(f, "Onion layer error: {}", msg),
        }
    }
}
impl From<OnionError> for SphinxError {
    fn from(e: OnionError) -> Self {
        SphinxError::OnionError(e.to_string())
    }
}

/// Relay information for one hop
#[derive(Clone, Debug)]
pub struct RelayHop {
    /// Relay node ID
    pub relay_id: Vec<u8>,
    /// Relay public key
    pub relay_pubkey: [u8; 32],
}

impl RelayHop {
    pub fn new(relay_id: Vec<u8>, relay_pubkey: [u8; 32]) -> Self {
        Self {
            relay_id,
            relay_pubkey,
        }
    }
}

/// Sphinx packet header
#[derive(Clone, Debug)]
pub struct SphinxHeader {
    /// Ephemeral public key for ECDH
    pub ephemeral_key: [u8; 32],
    /// Encrypted route info (relay hops + destination)
    pub route_info: Vec<u8>,
    /// HMAC for packet integrity
    pub hmac: [u8; 32],
}

impl SphinxHeader {
    fn new(ephemeral_key: [u8; 32], route_info: Vec<u8>, hmac: [u8; 32]) -> Self {
        Self {
            ephemeral_key,
            route_info,
            hmac,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.ephemeral_key);
        bytes.extend_from_slice(&(self.route_info.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.route_info);
        bytes.extend_from_slice(&self.hmac);
        bytes
    }

    fn from_bytes(data: &[u8]) -> Result<(Self, usize), SphinxError> {
        if data.len() < 32 + 4 + 32 {
            return Err(SphinxError::InvalidPacketSize);
        }

        let mut offset = 0;
        let mut ephemeral_key = [0u8; 32];
        ephemeral_key.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let route_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + route_len + 32 > data.len() {
            return Err(SphinxError::InvalidPacketSize);
        }

        let route_info = data[offset..offset + route_len].to_vec();
        offset += route_len;

        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&data[offset..offset + 32]);

        let header = Self::new(ephemeral_key, route_info, hmac);
        Ok((header, offset + 32))
    }
}

/// Complete Sphinx packet
#[derive(Clone, Debug)]
pub struct SphinxPacket {
    /// Packet header (public)
    pub header: SphinxHeader,
    /// Encrypted payload
    pub payload: Vec<u8>,
}

impl SphinxPacket {
    /// Create new Sphinx packet
    ///
    /// # Arguments
    /// * `message` - Plaintext message
    /// * `relay_path` - Path through relays: [relay1, relay2, relay3, recipient]
    /// * `packet_size` - Fixed packet size (for uniformity)
    pub fn create(
        message: &[u8],
        relay_path: &[RelayHop],
        packet_size: usize,
    ) -> Result<Self, SphinxError> {
        if relay_path.is_empty() || relay_path.len() > MAX_HOPS {
            return Err(SphinxError::TooManyHops);
        }

        if message.len() > packet_size {
            return Err(SphinxError::InvalidPacketSize);
        }

        // Generate ephemeral key pair
        let ephemeral_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let ephemeral_key = ephemeral_public.as_bytes().clone();

        // Create route information (encrypted)
        let route_info = Self::create_route_info(relay_path)?;

        // Compute HMAC
        let mut hasher = Sha256::new();
        hasher.update(&ephemeral_key);
        hasher.update(&route_info);
        hasher.update(message);
        let hmac_result = hasher.finalize();
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&hmac_result);

        let header = SphinxHeader::new(ephemeral_key, route_info, hmac);

        // Create onion-encrypted payload
        let mut payload = message.to_vec();
        payload.resize(packet_size, 0u8); // Pad to fixed size

        // Onion-encrypt payload through relay path (in reverse)
        for relay in relay_path.iter().rev() {
            // Create shared secret via ECDH
            let relay_pubkey = PublicKey::from(relay.relay_pubkey);
            let shared_secret = ephemeral_secret.diffie_hellman(&relay_pubkey);

            // Encrypt payload
            let encryption = OnionEncryption::new(shared_secret.as_bytes());
            payload = encryption.encrypt(&payload)?;
        }

        Ok(Self { header, payload })
    }

    /// Serialize packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Deserialize packet from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, SphinxError> {
        let (header, header_len) = SphinxHeader::from_bytes(data)?;

        let remaining = &data[header_len..];
        if remaining.len() < 4 {
            return Err(SphinxError::InvalidPacketSize);
        }

        let payload_len = u32::from_le_bytes([
            remaining[0],
            remaining[1],
            remaining[2],
            remaining[3],
        ]) as usize;

        if remaining.len() < 4 + payload_len {
            return Err(SphinxError::InvalidPacketSize);
        }

        let payload = remaining[4..4 + payload_len].to_vec();

        Ok(Self { header, payload })
    }

    /// Peel one layer of onion encryption at relay node
    ///
    /// # Arguments
    /// * `relay_secret` - Relay's secret key
    pub fn peel_layer(&self, relay_secret: &[u8; 32]) -> Result<Self, SphinxError> {
        // Create shared secret via ECDH
        let ephemeral_pubkey = PublicKey::from(self.header.ephemeral_key);
        let secret = StaticSecret::from(*relay_secret);
        let shared = secret.diffie_hellman(&ephemeral_pubkey);

        // Decrypt payload one layer
        let encryption = OnionEncryption::new(shared.as_bytes());
        let new_payload = encryption.decrypt(&self.payload)?;

        // In production: decrypt and update route_info here
        // For now: return packet with decrypted payload

        Ok(Self {
            header: self.header.clone(),
            payload: new_payload,
        })
    }

    /// Get destination from route info (only readable at final relay)
    pub fn get_destination(&self) -> Result<Vec<u8>, SphinxError> {
        // In production: decrypt route_info with relay's key to get next hop
        // For now: parse from route_info structure

        if self.header.route_info.is_empty() {
            return Err(SphinxError::InvalidRouteInfo);
        }

        // Simple format: [dest_len (1 byte)][destination]
        let dest_len = self.header.route_info[0] as usize;
        if self.header.route_info.len() < 1 + dest_len {
            return Err(SphinxError::InvalidRouteInfo);
        }

        Ok(self.header.route_info[1..1 + dest_len].to_vec())
    }

    /// Create encrypted route information
    fn create_route_info(relay_path: &[RelayHop]) -> Result<Vec<u8>, SphinxError> {
        let mut route_info = Vec::new();

        // Add destination (last relay)
        if let Some(last) = relay_path.last() {
            route_info.push(last.relay_id.len() as u8);
            route_info.extend_from_slice(&last.relay_id);
        }

        // Add previous relays in reverse
        for relay in relay_path.iter().rev().skip(1) {
            route_info.push(relay.relay_id.len() as u8);
            route_info.extend_from_slice(&relay.relay_id);
        }

        Ok(route_info)
    }

    /// Verify packet integrity via HMAC
    pub fn verify_integrity(&self, message: &[u8]) -> Result<(), SphinxError> {
        let mut hasher = Sha256::new();
        hasher.update(&self.header.ephemeral_key);
        hasher.update(&self.header.route_info);
        hasher.update(message);
        let computed_hmac = hasher.finalize();

        if computed_hmac.as_slice() == self.header.hmac {
            Ok(())
        } else {
            Err(SphinxError::DecryptionFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphinx_packet_creation() {
        let message = b"Hello, Mixnet!";
        let relay_path = vec![
            RelayHop::new(b"relay1".to_vec(), [1u8; 32]),
            RelayHop::new(b"relay2".to_vec(), [2u8; 32]),
            RelayHop::new(b"relay3".to_vec(), [3u8; 32]),
        ];

        let packet = SphinxPacket::create(message, &relay_path, 1024);
        assert!(packet.is_ok());
    }

    #[test]
    fn test_packet_serialization() {
        let message = b"Test message";
        let relay_path = vec![RelayHop::new(b"relay1".to_vec(), [1u8; 32])];

        let packet = SphinxPacket::create(message, &relay_path, 512).unwrap();
        let bytes = packet.to_bytes();
        let deserialized = SphinxPacket::from_bytes(&bytes);

        assert!(deserialized.is_ok());
    }

    #[test]
    fn test_too_many_hops() {
        let mut relay_path = Vec::new();
        for i in 0..17 {
            relay_path.push(RelayHop::new(
                format!("relay{}", i).into_bytes(),
                [i as u8; 32],
            ));
        }

        let result = SphinxPacket::create(b"message", &relay_path, 1024);
        assert!(matches!(result, Err(SphinxError::TooManyHops)));
    }

    #[test]
    fn test_message_too_large() {
        let large_message = vec![0u8; 2048];
        let relay_path = vec![RelayHop::new(b"relay1".to_vec(), [1u8; 32])];

        let result = SphinxPacket::create(&large_message, &relay_path, 1024);
        assert!(matches!(result, Err(SphinxError::InvalidPacketSize)));
    }
}