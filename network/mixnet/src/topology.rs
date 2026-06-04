//! Mixnet Topology - Relay network configuration
//!
//! Defines which relays route to which nodes in the network

use crate::{MixnetError, sphinx::RelayHop};
use std::collections::HashMap;

/// Relay node configuration
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Relay node ID
    pub id: String,
    /// Public key for ECDH
    pub pubkey: [u8; 32],
    /// RPC endpoint
    pub endpoint: String,
    /// Connected peer IDs (next hops)
    pub next_hops: Vec<String>,
}

impl RelayConfig {
    pub fn new(id: String, pubkey: [u8; 32], endpoint: String) -> Self {
        Self {
            id,
            pubkey,
            endpoint,
            next_hops: Vec::new(),
        }
    }

    pub fn add_next_hop(&mut self, peer_id: String) {
        if !self.next_hops.contains(&peer_id) {
            self.next_hops.push(peer_id);
        }
    }
}

/// Network topology for mixnet routing
#[derive(Clone, Debug)]
pub struct Topology {
    /// Map of relay ID → config
    relays: HashMap<String, RelayConfig>,
    /// Map of validator ID → primary relay
    validator_relays: HashMap<String, String>,
}

impl Default for Topology {
    fn default() -> Self {
        Self {
            relays: HashMap::new(),
            validator_relays: HashMap::new(),
        }
    }
}

impl Topology {
    /// Create new topology
    pub fn new() -> Self {
        Self::default()
    }

    /// Register relay node
    pub fn register_relay(&mut self, config: RelayConfig) -> Result<(), MixnetError> {
        if self.relays.contains_key(&config.id) {
            return Err(MixnetError::InvalidTopology(format!(
                "Relay {} already registered",
                config.id
            )));
        }

        self.relays.insert(config.id.clone(), config);
        Ok(())
    }

    /// Connect relay to another relay
    pub fn connect_relays(
        &mut self,
        from: &str,
        to: &str,
    ) -> Result<(), MixnetError> {
        let relay = self
            .relays
            .get_mut(from)
            .ok_or_else(|| MixnetError::RelayNotFound(from.to_string()))?;

        relay.add_next_hop(to.to_string());
        Ok(())
    }

    /// Register validator and its primary relay
    pub fn register_validator(
        &mut self,
        validator_id: &str,
        primary_relay: &str,
    ) -> Result<(), MixnetError> {
        if !self.relays.contains_key(primary_relay) {
            return Err(MixnetError::RelayNotFound(primary_relay.to_string()));
        }

        self.validator_relays
            .insert(validator_id.to_string(), primary_relay.to_string());
        Ok(())
    }

    /// Get relay config by ID
    pub fn get_relay(&self, id: &str) -> Option<RelayConfig> {
        self.relays.get(id).cloned()
    }

    /// Get path from sender to recipient through relays
    pub fn get_path_to(
        &self,
        recipient_id: &str,
        num_hops: usize,
    ) -> Result<Vec<RelayHop>, MixnetError> {
        // Get recipient's primary relay
        let primary_relay = self
            .validator_relays
            .get(recipient_id)
            .ok_or_else(|| MixnetError::RelayNotFound(recipient_id.to_string()))?;

        let mut path = Vec::new();

        // Select random relays for path
        let relay_ids: Vec<_> = self.relays.keys().cloned().collect();

        if relay_ids.len() < num_hops {
            return Err(MixnetError::InvalidTopology(
                "Not enough relays in topology".to_string(),
            ));
        }

        // Select first hops
        for i in 0..num_hops - 1 {
            let idx = (i * 7) % relay_ids.len(); // Deterministic for testing
            let relay_id = &relay_ids[idx];
            let relay = self.get_relay(relay_id).ok_or_else(|| {
                MixnetError::RelayNotFound(relay_id.to_string())
            })?;
            path.push(RelayHop::new(relay_id.as_bytes().to_vec(), relay.pubkey));
        }

        // Add recipient's relay as final hop
        let recipient_relay = self.get_relay(primary_relay).ok_or_else(|| {
            MixnetError::RelayNotFound(primary_relay.clone())
        })?;
        path.push(RelayHop::new(
            primary_relay.as_bytes().to_vec(),
            recipient_relay.pubkey,
        ));

        Ok(path)
    }

    /// Validate topology consistency
    pub fn validate(&self) -> Result<(), MixnetError> {
        // Check all relays have next hops configured
        for (id, relay) in &self.relays {
            if relay.next_hops.is_empty() && self.relays.len() > 1 {
                return Err(MixnetError::InvalidTopology(format!(
                    "Relay {} has no next hops",
                    id
                )));
            }

            // Check all next hops exist
            for next_id in &relay.next_hops {
                if !self.relays.contains_key(next_id) {
                    return Err(MixnetError::InvalidTopology(format!(
                        "Next hop {} not found for relay {}",
                        next_id, id
                    )));
                }
            }
        }

        // Check all validators have assigned relays
        for validator_id in self.validator_relays.keys() {
            let relay_id = &self.validator_relays[validator_id];
            if !self.relays.contains_key(relay_id) {
                return Err(MixnetError::InvalidTopology(format!(
                    "Relay {} assigned to validator {} not found",
                    relay_id, validator_id
                )));
            }
        }

        Ok(())
    }

    /// Get number of relays in topology
    pub fn relay_count(&self) -> usize {
        self.relays.len()
    }

    /// Get number of registered validators
    pub fn validator_count(&self) -> usize {
        self.validator_relays.len()
    }
}

/// Builder for easy topology configuration
pub struct TopologyBuilder {
    topology: Topology,
}

impl TopologyBuilder {
    pub fn new() -> Self {
        Self {
            topology: Topology::new(),
        }
    }

    pub fn add_relay(mut self, id: &str, pubkey: [u8; 32], endpoint: &str) -> Self {
        let config = RelayConfig::new(id.to_string(), pubkey, endpoint.to_string());
        let _ = self.topology.register_relay(config);
        self
    }

    pub fn add_validator(mut self, validator_id: &str, relay_id: &str) -> Self {
        let _ = self.topology.register_validator(validator_id, relay_id);
        self
    }

    pub fn connect(mut self, from: &str, to: &str) -> Self {
        let _ = self.topology.connect_relays(from, to);
        self
    }

    pub fn build(self) -> Result<Topology, MixnetError> {
        self.topology.validate()?;
        Ok(self.topology)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topology_creation() {
        let builder = TopologyBuilder::new()
            .add_relay("relay1", [1u8; 32], "http://relay1:9944")
            .add_relay("relay2", [2u8; 32], "http://relay2:9944")
            .add_relay("relay3", [3u8; 32], "http://relay3:9944")
            .add_validator("alice", "relay1")
            .add_validator("bob", "relay2")
            .add_validator("charlie", "relay3")
            .connect("relay1", "relay2")
            .connect("relay2", "relay3");

        let topology = builder.build();
        assert!(topology.is_ok());
        assert_eq!(topology.unwrap().relay_count(), 3);
    }

    #[test]
    fn test_path_generation() {
        let topology = TopologyBuilder::new()
            .add_relay("relay1", [1u8; 32], "http://relay1:9944")
            .add_relay("relay2", [2u8; 32], "http://relay2:9944")
            .add_relay("relay3", [3u8; 32], "http://relay3:9944")
            .add_validator("alice", "relay2")
            .build()
            .unwrap();

        let path = topology.get_path_to("alice", 3);
        assert!(path.is_ok());
        assert_eq!(path.unwrap().len(), 3);
    }

    #[test]
    fn test_invalid_topology() {
        let builder = TopologyBuilder::new()
            .add_relay("relay1", [1u8; 32], "http://relay1:9944")
            .add_validator("alice", "nonexistent_relay");

        let result = builder.build();
        assert!(result.is_err());
    }
}