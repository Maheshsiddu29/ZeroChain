Zero Chain ZK Prover - Quick Start Guide

Complete command reference for generating and verifying zero-knowledge proofs.
Prerequisites

Bash

# Navigate to project root
```
cd ZeroChain
```
# Build all binaries (one-time)
```
cargo build --release --workspace
```
Quick Start (3 Commands)
1. Generate Keys (One-Time Setup)

Bash
```
cargo run --release -p zk-prover -- setup --circuit transfer --output-dir keys
```
2. Generate a Proof

Bash

# First, create a witness file
```
cat > witness.json << 'EOF'
{
  "input_notes": [{
    "value": "100000000000000",
    "asset_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "blinding": "0x0102030405060708091011121314151617181920212223242526272829303132",
    "nullifier_key": "0x1112131415161718192021222324252627282930313233343536373839404142",
    "owner_pubkey": "0x0000000000000000000000000000000000000000000000000000000000000000"
  }],
  "output_notes": [{
    "value": "100000000000000",
    "asset_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "blinding": "0x3132333435363738394041424344454647484950515253545556575859606162",
    "recipient_pubkey": "0x2122232425262728293031323334353637383940414243444546474849505152"
  }]
}
EOF
```

# Generate proof
```
cargo run --release -p zk-prover -- transfer --witness witness.json --proving-key keys/transfer.pk --output proof.bin
```
3. Verify the Proof

Bash
```
cargo run --release -p zk-prover -- verify --proof proof.bin --vk keys/transfer.vk
```
Expected Output:

text

[INFO] Verifying proof...
[INFO] Loading verifying key from keys/transfer.vk (840 bytes)
[INFO] Verifying key loaded
[INFO] Verifying transfer proof with 5 public inputs...
[INFO] Verification result: true
[INFO] ✓ Proof is VALID



Bash

# Generate circuit keys
```
cargo run --release -p zk-prover -- setup --circuit transfer --output-dir keys
```
Output:

text

[INFO] Running trusted setup for TransferCircuit (1-in, 1-out)...
[INFO] Setup complete
[INFO] Proving key saved to keys/transfer.pk (6384 bytes)
[INFO] Verifying key saved to keys/transfer.vk (840 bytes)

Files Created:

    keys/transfer.pk (6 KB) - Proving key
    keys/transfer.vk (840 bytes) - Verifying key

Step 2: Create Witness

Bash
```
cat > witness.json << 'EOF'
{
  "input_notes": [{
    "value": "100000000000000",
    "asset_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "blinding": "0x0102030405060708091011121314151617181920212223242526272829303132",
    "nullifier_key": "0x1112131415161718192021222324252627282930313233343536373839404142",
    "owner_pubkey": "0x0000000000000000000000000000000000000000000000000000000000000000"
  }],
  "output_notes": [{
    "value": "100000000000000",
    "asset_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "blinding": "0x3132333435363738394041424344454647484950515253545556575859606162",
    "recipient_pubkey": "0x2122232425262728293031323334353637383940414243444546474849505152"
  }]
}
EOF
```
Step 3: Generate Proof

Bash
```
cargo run --release -p zk-prover -- transfer \
  --witness witness.json \
  --proving-key keys/transfer.pk \
  --output proof.bin
```
Output:

text

[INFO] Generating shielded transfer proof...
[INFO] Loading proving key from keys/transfer.pk (6384 bytes)
[INFO] Proving key loaded
[INFO] Generating transfer proof...
[INFO]   Inputs: 1, Outputs: 1
[INFO] Proof generated successfully
[INFO] Proof saved to proof.bin
[INFO] Submission size: 419 bytes

File Created:

    proof.bin (419 bytes) - ZK Proof

Step 4: Verify Proof

Bash
```
cargo run --release -p zk-prover -- verify \
  --proof proof.bin \
  --vk keys/transfer.vk
```
Output (Success):

text

[INFO] Verifying proof...
[INFO] Loading verifying key from keys/transfer.vk (840 bytes)
[INFO] Verifying key loaded
[INFO] Verifying transfer proof with 5 public inputs...
[INFO] Verification result: true
[INFO] ✓ Proof is VALID

Output (Failure):

text

[INFO] Verification result: false
[ERROR] ✗ Proof is INVALID

One-Line Commands
Prove (with auto-setup if keys missing)

Bash
```
cargo run --release -p zk-prover -- transfer --witness witness.json --output proof.bin
```
Verify

Bash
```
cargo run --release -p zk-prover -- verify --proof proof.bin --vk keys/transfer.vk
```
Multiple Proofs

Bash

# Proof 1
```
cargo run --release -p zk-prover -- transfer --witness witness.json --proving-key keys/transfer.pk --output proof1.bin
cargo run --release -p zk-prover -- verify --proof proof1.bin --vk keys/transfer.vk
```

# Proof 2  
```
cargo run --release -p zk-prover -- transfer --witness witness.json --proving-key keys/transfer.pk --output proof2.bin
cargo run --release -p zk-prover -- verify --proof proof2.bin --vk keys/transfer.vk
```

# Proof 3
```
cargo run --release -p zk-prover -- transfer --witness witness.json --proving-key keys/transfer.pk --output proof3.bin
cargo run --release -p zk-prover -- verify --proof proof3.bin --vk keys/transfer.vk
```




Bash

# Test all components
```
cargo test --release -p transfer-circuit
cargo test --release -p zk-prover
```

# Generate test vectors
```
cargo test --release -p transfer-circuit --test generate_test_vector -- --ignored --nocapture
```

# Verify test vectors
```
cargo test --release -p transfer-circuit --test test_vectors -- --ignored --nocapture
```

Troubleshooting
Proof is INVALID

Problem: Verification fails

Solution: Keys and witness must match the same circuit structure (1-in-1-out)

Bash

# Delete old keys
```
rm -rf keys/
```

# Regenerate
```
cargo run --release -p zk-prover -- setup --circuit transfer --output-dir keys
```
# Try again
```
cargo run --release -p zk-prover -- transfer --witness witness.json --proving-key keys/transfer.pk --output proof.bin
cargo run --release -p zk-prover -- verify --proof proof.bin --vk keys/transfer.vk
```

Slow Performance

Problem: Proof generation takes >5 seconds

Solution: Always use --release flag

Bash

# Wrong (slow)
```
cargo run -p zk-prover -- transfer --witness witness.json --output proof.bin
```
# Right (fast)
```
cargo run --release -p zk-prover -- transfer --witness witness.json --output proof.bin
```
Keys Not Found

Problem: Failed to read proving key file

Solution: Run setup first

Bash
```
cargo run --release -p zk-prover -- setup --circuit transfer --output-dir keys
```



To prove and verify:

Bash

# 1. Setup (once)
```
cargo run --release -p zk-prover -- setup --circuit transfer --output-dir keys
```
# 2. Create witness.json (see above)

# 3. Prove
```
cargo run --release -p zk-prover -- transfer --witness witness.json --proving-key keys/transfer.pk --output proof.bin
```
# 4. Verify
```
cargo run --release -p zk-prover -- verify --proof proof.bin --vk keys/transfer.vk
```