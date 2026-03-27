
use origin_circuit::*;
use ark_bn254::Fr;
use ark_std::UniformRand;

#[test]
fn test_realistic_chain_folding() {
    println!("\n=== Testing Realistic Chain Folding ===\n");
    
    let mut rng = ark_std::test_rng();
    let genesis_hash = Fr::rand(&mut rng);
    let mut accumulator = ZkOriginAccumulator::genesis(genesis_hash);
    
    let mut prev_root = genesis_hash;
    
    for height in 1..=5 {
        let new_root = Fr::rand(&mut rng);
        let tx_hash = Fr::rand(&mut rng);
        
        println!("Folding block {}...", height);
        accumulator
            .fold_block(prev_root, new_root, height, tx_hash)
            .expect(&format!("Block {} fold failed", height));
        
        prev_root = new_root;
    }
    
    println!("\nVerifying entire chain...");
    let valid = accumulator.verify().expect("Verification failed");
    assert!(valid);
    
    println!("\nCompressing proof...");
    let compressed = accumulator.compress().expect("Compression failed");
    
    println!("\n Chain Summary:");
    println!("   Blocks: {}", accumulator.current_height);
    println!("   Compressed proof size: {} bytes", compressed.len());
    println!("   Average per block: {} bytes", compressed.len() / (accumulator.current_height as usize));
}

#[test]
fn test_block_retrieval() {
    let mut rng = ark_std::test_rng();
    let genesis_hash = Fr::rand(&mut rng);
    let mut accumulator = ZkOriginAccumulator::genesis(genesis_hash);
    
    let mut prev_root = genesis_hash;
    
    for height in 1..=3 {
        let new_root = Fr::rand(&mut rng);
        accumulator.fold_block(prev_root, new_root, height, Fr::from(0u64)).unwrap();
        prev_root = new_root;
    }
    
    // Retrieve specific blocks
    let block_1 = accumulator.get_block_proof(1).unwrap();
    assert_eq!(block_1.block_height, 1);
    
    let block_3 = accumulator.get_block_proof(3).unwrap();
    assert_eq!(block_3.block_height, 3);
    
    // Non-existent block
    let block_10 = accumulator.get_block_proof(10);
    assert!(block_10.is_none());
    
    println!(" Block retrieval working");
}

#[test]
fn test_persistence() {
    let mut rng = ark_std::test_rng();
    let genesis_hash = Fr::rand(&mut rng);
    let mut accumulator = ZkOriginAccumulator::genesis(genesis_hash);
    
    let mut prev_root = genesis_hash;
    for height in 1..=5 {
        let new_root = Fr::rand(&mut rng);
        accumulator.fold_block(prev_root, new_root, height, Fr::from(0u64)).unwrap();
        prev_root = new_root;
    }
    
    // Save
    let bytes = accumulator.to_bytes().unwrap();
    println!("Saved {} blocks to {} bytes", accumulator.current_height, bytes.len());
    
    // Load
    let restored = ZkOriginAccumulator::from_bytes(&bytes).unwrap();
    
    assert_eq!(restored.current_height, accumulator.current_height);
    assert!(restored.verify().unwrap());
    
    println!(" Persistence working");
}
