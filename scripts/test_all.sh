#!/usr/bin/env bash
# Test all Zero Chain components

set -euo pipefail

echo "==================================="
echo " Zero Chain Full Component Test"
echo "==================================="

# Test crypto library
echo -e "\n[1/5] Testing crypto library..."
cargo test -p zc-crypto --verbose

# Test circuits
echo -e "\n[2/5] Testing transfer circuit..."
cargo test -p transfer-circuit --verbose

echo -e "\n[3/5] Testing origin circuit..."
cargo test -p origin-circuit --verbose

# Test prover
echo -e "\n[4/5] Testing prover..."
cargo test -p zk-prover --verbose

echo -e "\n[5/5] Testing membership circuit..."
cargo test -p membership-circuit --verbose





# Build CLI
echo -e "\n[BONUS] Building CLI..."
cargo build -p zero-chain-cli --release

echo -e "\n All tests passed!"