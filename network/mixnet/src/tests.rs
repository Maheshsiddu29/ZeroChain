//! Integration tests for mixnet

#[cfg(test)]
mod integration_tests {
    use crate::{
        onion::OnionEncryption, relay::RelayNode, sphinx::{RelayHop, SphinxPacket},
        topology::TopologyBuilder, MixnetConfig,
    };
    use x25519_dalek::{StaticSecret, PublicKey};

    /// Derive the X25519 public key from a raw secret-key byte array.
    ///
    /// The relay's public key stored in `RelayHop` must correspond to its
    /// secret key so that ECDH during packet creation and during `peel_layer`
    /// produce the same shared secret.  Using the secret bytes directly as a
    /// public key does NOT satisfy this property.
    fn pubkey_from_secret(secret: [u8; 32]) -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(secret)).as_bytes()
    }

    #[test]
    fn test_full_mixnet_flow() {
        let sk1 = [1u8; 32];
        let sk2 = [2u8; 32];
        let sk3 = [3u8; 32];

        // Verify topology builds and validates correctly.
        let _ = TopologyBuilder::new()
            .add_relay("relay1", pubkey_from_secret(sk1), "http://relay1:9944")
            .add_relay("relay2", pubkey_from_secret(sk2), "http://relay2:9944")
            .add_relay("relay3", pubkey_from_secret(sk3), "http://relay3:9944")
            .add_validator("alice", "relay1")
            .add_validator("bob", "relay2")
            .add_validator("charlie", "relay3")
            .connect("relay1", "relay2")
            .connect("relay2", "relay3")
            .build()
            .unwrap();

        // Build the path in known order so each RelayNode peels exactly the
        // layer that was encrypted for its public key.  get_path_to draws from
        // a HashMap whose iteration order is non-deterministic, which would make
        // the relay-to-position assignment unpredictable.
        let path = vec![
            RelayHop::new(b"relay1".to_vec(), pubkey_from_secret(sk1)),
            RelayHop::new(b"relay2".to_vec(), pubkey_from_secret(sk2)),
            RelayHop::new(b"relay3".to_vec(), pubkey_from_secret(sk3)),
        ];

        let message = b"Secret consensus vote";
        let packet = SphinxPacket::create(message, &path, 1024).unwrap();
        println!("Created packet, size: {}", packet.to_bytes().len());

        // Relay 1 peels its layer
        let mut relay1 = RelayNode::new("relay1".to_string(), sk1);
        assert!(relay1.receive_packet(packet.clone()).is_ok());
        assert_eq!(relay1.queue_size(), 1);
        let packet2 = relay1.process_next_packet().unwrap().unwrap();
        println!("Relay1 processed, payload size: {}", packet2.payload.len());

        // Relay 2 peels its layer
        let mut relay2 = RelayNode::new("relay2".to_string(), sk2);
        assert!(relay2.receive_packet(packet2.clone()).is_ok());
        let packet3 = relay2.process_next_packet().unwrap().unwrap();
        println!("Relay2 processed, payload size: {}", packet3.payload.len());

        // Relay 3 receives (final hop — no further peeling in this test)
        let mut relay3 = RelayNode::new("relay3".to_string(), sk3);
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
            RelayHop::new(b"relay1".to_vec(), pubkey_from_secret([1u8; 32])),
            RelayHop::new(b"relay2".to_vec(), pubkey_from_secret([2u8; 32])),
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
        let messages = vec![
            &b"Short"[..],
            &b"This is a medium length message for testing"[..],
            &b"A very long message that would normally be much larger and should still be padded to the same size as shorter messages to maintain uniformity and anonymity in the network"[..],
        ];

        let path = vec![RelayHop::new(b"relay".to_vec(), pubkey_from_secret([1u8; 32]))];
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
        let path = vec![RelayHop::new(b"relay".to_vec(), pubkey_from_secret([1u8; 32]))];
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
        let sk1 = [1u8; 32];
        let sk2 = [2u8; 32];
        let sk3 = [3u8; 32];

        let path = vec![
            RelayHop::new(b"relay1".to_vec(), pubkey_from_secret(sk1)),
            RelayHop::new(b"relay2".to_vec(), pubkey_from_secret(sk2)),
            RelayHop::new(b"relay3".to_vec(), pubkey_from_secret(sk3)),
        ];

        // Create multiple packets
        let messages: Vec<&[u8]> = vec![b"msg1", b"msg2", b"msg3"];
        let mut relay = RelayNode::new("relay1".to_string(), sk1);

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
