//! Integration tests for mixnet

#[cfg(test)]
mod integration_tests {
    use crate::{
        onion::OnionEncryption, relay::RelayNode, sphinx::{RelayHop, SphinxPacket},
        topology::TopologyBuilder, MixnetConfig,
    };

    #[test]
    fn test_full_mixnet_flow() {
        // Setup: 3-relay network
        let topology = TopologyBuilder::new()
            .add_relay("relay1", [1u8; 32], "http://relay1:9944")
            .add_relay("relay2", [2u8; 32], "http://relay2:9944")
            .add_relay("relay3", [3u8; 32], "http://relay3:9944")
            .add_validator("alice", "relay1")
            .add_validator("bob", "relay2")
            .add_validator("charlie", "relay3")
            .connect("relay1", "relay2")
            .connect("relay2", "relay3")
            .build()
            .unwrap();

        // Create message from Alice to Charlie
        let message = b"Secret consensus vote";
        let path = topology.get_path_to("charlie", 3).unwrap();

        // Create Sphinx packet
        let packet = SphinxPacket::create(message, &path, 1024).unwrap();
        println!("Created packet, size: {}", packet.to_bytes().len());

        // Relay 1 receives and processes
        let mut relay1 = RelayNode::new("relay1".to_string(), [1u8; 32]);
        assert!(relay1.receive_packet(packet.clone()).is_ok());
        assert_eq!(relay1.queue_size(), 1);

        // Relay 1 peels layer
        let packet2 = relay1.process_next_packet().unwrap().unwrap();
        println!(
            "Relay1 processed, payload size: {}",
            packet2.payload.len()
        );

        // Relay 2 receives and processes
        let mut relay2 = RelayNode::new("relay2".to_string(), [2u8; 32]);
        assert!(relay2.receive_packet(packet2.clone()).is_ok());

        let packet3 = relay2.process_next_packet().unwrap().unwrap();
        println!(
            "Relay2 processed, payload size: {}",
            packet3.payload.len()
        );

        // Relay 3 receives (final relay)
        let mut relay3 = RelayNode::new("relay3".to_string(), [3u8; 32]);
        assert!(relay3.receive_packet(packet3).is_ok());

        println!("✓ Message successfully routed through 3-relay mixnet");
    }

    #[test]
    fn test_onion_layer_peeling() {
        // Create shared secrets for each relay
        let secrets = [[1u8; 32], [2u8; 32], [3u8; 32]];

        let plaintext = b"Consensus message";

        // Encrypt through relays
        let encrypted =
            OnionEncryption::encrypt_layers(plaintext, &secrets).unwrap();

        // Peel layers
        let mut data = encrypted;
        for (i, secret) in secrets.iter().enumerate() {
            let decryptor = OnionEncryption::new(secret);
            data = decryptor.decrypt(&data).unwrap();
            println!("Peeled layer {} of {}", i + 1, secrets.len());
        }

        assert_eq!(data, plaintext);
    }

    #[test]
    fn test_packet_anonymity() {
        // Two messages from different sources to same destination
        let msg1 = b"Message A";
        let msg2 = b"Message B";

        let path = vec![
            RelayHop::new(b"relay1".to_vec(), [1u8; 32]),
            RelayHop::new(b"relay2".to_vec(), [2u8; 32]),
        ];

        let packet1 = SphinxPacket::create(msg1, &path, 512).unwrap();
        let packet2 = SphinxPacket::create(msg2, &path, 512).unwrap();

        // Packets should look different even for similar messages
        let bytes1 = packet1.to_bytes();
        let bytes2 = packet2.to_bytes();

        assert_ne!(bytes1, bytes2);
        // Ephemeral keys should differ
        assert_ne!(
            &bytes1[..32],
            &bytes2[..32],
            "Packets should use different ephemeral keys"
        );

        println!("✓ Packet anonymity verified");
    }

    #[test]
    fn test_fixed_packet_size() {
        let mut messages = vec![
            &b"Short"[..],
            &b"This is a medium length message for testing"[..],
            &b"A very long message that would normally be much larger and should still be padded to the same size as shorter messages to maintain uniformity and anonymity in the network"[..],
        ];

        let path = vec![RelayHop::new(b"relay".to_vec(), [1u8; 32])];
        let packet_size = 1024;

        let packets: Vec<_> = messages
            .iter()
            .map(|msg| SphinxPacket::create(msg, &path, packet_size).unwrap())
            .collect();

        // All packets should have same size
        let sizes: Vec<_> = packets
            .iter()
            .map(|p| p.to_bytes().len())
            .collect();

        assert!(sizes.iter().all(|&s| s == sizes[0]));
        println!(
            "✓ All {} packets have uniform size: {} bytes",
            packets.len(),
            sizes[0]
        );
    }

    #[test]
    fn test_relay_deduplication() {
        let mut relay = RelayNode::new("relay".to_string(), [1u8; 32]);

        let message = b"test";
        let path = vec![RelayHop::new(b"relay".to_vec(), [1u8; 32])];
        let packet = SphinxPacket::create(message, &path, 512).unwrap();

        // First packet accepted
        assert!(relay.receive_packet(packet.clone()).is_ok());
        assert_eq!(relay.queue_size(), 1);

        // Duplicate rejected
        let result = relay.receive_packet(packet);
        assert!(result.is_err());

        println!("✓ Relay correctly rejects duplicate packets");
    }

    #[test]
    fn test_cascade_processing() {
        let path = vec![
            RelayHop::new(b"relay1".to_vec(), [1u8; 32]),
            RelayHop::new(b"relay2".to_vec(), [2u8; 32]),
            RelayHop::new(b"relay3".to_vec(), [3u8; 32]),
        ];

        // Create multiple packets
        let messages = vec![b"msg1", b"msg2", b"msg3"];
        let mut relay = RelayNode::new("relay1".to_string(), [1u8; 32]);

        for msg in &messages {
            let packet = SphinxPacket::create(*msg, &path, 512).unwrap();
            relay.receive_packet(packet).ok();
        }

        assert_eq!(relay.queue_size(), 3);

        // Process all
        let processed = relay.process_all_packets().unwrap();
        assert_eq!(processed.len(), 3);
        assert_eq!(relay.queue_size(), 0);
        assert_eq!(relay.processed_count(), 3);

        println!("✓ Processed 3 packets in cascade");
    }
}