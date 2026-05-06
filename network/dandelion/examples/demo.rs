//! Dandelion++ protocol demonstration
//!
//! Run with: cargo run --example dandelion_demo -p network-dandelion

use network_dandelion::{DandelionCore, DandelionConfig};
use std::time::Duration;

fn main() {
    println!("=== Dandelion++ Protocol Demo ===\n");

    // Create protocol instance
    let config = DandelionConfig {
        stem_hops: 4,
        safety_timeout: Duration::from_secs(30),
        stem_probability: 0.6,
    };

    let mut dandelion = DandelionCore::new(config);

    // Simulate 5 transactions
    let peers = vec![
        vec![1, 2, 3],  // Peer A
        vec![4, 5, 6],  // Peer B
        vec![7, 8, 9],  // Peer C
    ];

    println!("Network: {} peers\n", peers.len());

    for i in 0..5 {
        let tx_hash = format!("tx_{}", i).into_bytes();
        println!("Processing {}...", String::from_utf8_lossy(&tx_hash));

        let decision = dandelion.process_tx(tx_hash.clone(), &peers);

        match decision {
            network_dandelion::DandelionDecision::Stem(peer) => {
                println!("  → STEM phase: forward to peer {:?}", peer);
            }
            network_dandelion::DandelionDecision::Fluff => {
                println!("  → FLUFF phase: broadcast to all peers");
            }
        }
    }

    println!("\nDemo complete! {} transactions tracked", dandelion.stem_count());
}