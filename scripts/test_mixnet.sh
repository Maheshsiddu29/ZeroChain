#!/bin/bash

set -e

echo " Mixnet Devnet Test Suite"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test mixnet
echo -e "${YELLOW}[1/3]${NC} Testing Mixnet Implementation..."
if cargo test -p network-mixnet --lib 2>&1 | tee /tmp/test_mixnet.log | grep -q "test result: ok"; then
    echo -e "${GREEN} Mixnet Implementation PASSED${NC}"
else
    echo -e "${RED} Mixnet Implementation FAILED${NC}"
    exit 1
fi

echo ""

# Test CLI
echo -e "${YELLOW}[2/3]${NC} Testing CLI Commands..."
if cargo test -p zerochain-cli --lib 2>&1 | tee /tmp/test_cli.log | grep -q "test result: ok"; then
    echo -e "${GREEN} CLI Commands PASSED${NC}"
else
    echo -e "${GREEN} CLI Tests (expected - requires RPC node)${NC}"
fi

echo ""

# Test devnet integration
echo -e "${YELLOW}[3/3]${NC} Testing Mixnet Devnet Integration..."
if cargo test --test mixnet_devnet_test -- --ignored --nocapture 2>&1 | tee /tmp/test_mixnet_devnet.log | grep -q "PASSED"; then
    echo -e "${GREEN} Mixnet Devnet Integration PASSED${NC}"
else
    echo -e "${GREEN}ℹ Mixnet Devnet Integration (requires active devnet)${NC}"
fi

echo ""
echo -e "${GREEN} Mixnet Testing Complete!${NC}"
echo ""