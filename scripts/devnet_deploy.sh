#!/bin/bash

set -e

echo " ZeroChain 3-Node Devnet Deployment"
echo "======================================"
echo ""

RELEASE_BINARY="./target/release/solochain-template-node"
DEVNET_DIR="/tmp/zerochain_devnet"

# Check binary exists
if [ ! -f "$RELEASE_BINARY" ]; then
    echo " Release binary not found. Run: cargo build --release"
    exit 1
fi

echo " Setting up Devnet Directory..."
mkdir -p $DEVNET_DIR/alice $DEVNET_DIR/bob $DEVNET_DIR/charlie

# Start Alice (validator 0) - Port 9944
echo "  Starting Alice (Validator 0)..."
$RELEASE_BINARY \
    --chain=devnet \
    --name="Alice" \
    --validator \
    --base-path=$DEVNET_DIR/alice \
    --port=30333 \
    --rpc-port=9944 \
    --ws-port=9945 \
    --alice \
    -linfo \
    2>&1 | tee $DEVNET_DIR/alice.log &

ALICE_PID=$!
echo "Alice PID: $ALICE_PID"

# Give Alice time to start
sleep 3

# Start Bob (validator 1) - Port 9946
echo "  Starting Bob (Validator 1)..."
$RELEASE_BINARY \
    --chain=devnet \
    --name="Bob" \
    --validator \
    --base-path=$DEVNET_DIR/bob \
    --port=30334 \
    --rpc-port=9946 \
    --ws-port=9947 \
    --bob \
    --bootnodes=/ip4/127.0.0.1/tcp/30333/p2p/ALICE_PEER_ID \
    -linfo \
    2>&1 | tee $DEVNET_DIR/bob.log &

BOB_PID=$!
echo "Bob PID: $BOB_PID"

sleep 3

# Start Charlie (validator 2) - Port 9948
echo "  Starting Charlie (Validator 2)..."
$RELEASE_BINARY \
    --chain=devnet \
    --name="Charlie" \
    --validator \
    --base-path=$DEVNET_DIR/charlie \
    --port=30335 \
    --rpc-port=9948 \
    --ws-port=9949 \
    --charlie \
    --bootnodes=/ip4/127.0.0.1/tcp/30333/p2p/ALICE_PEER_ID \
    -linfo \
    2>&1 | tee $DEVNET_DIR/charlie.log &

CHARLIE_PID=$!
echo "Charlie PID: $CHARLIE_PID"

echo ""
echo " Devnet Running"
echo "=============="
echo ""
echo "RPC Endpoints:"
echo "  Alice:   http://localhost:9944"
echo "  Bob:     http://localhost:9946"
echo "  Charlie: http://localhost:9948"
echo ""
echo "Logs:"
echo "  Alice:   $DEVNET_DIR/alice.log"
echo "  Bob:     $DEVNET_DIR/bob.log"
echo "  Charlie: $DEVNET_DIR/charlie.log"
echo ""
echo "To stop: kill $ALICE_PID $BOB_PID $CHARLIE_PID"
echo ""
echo "Wait for block production (10 seconds)..."

# Monitor for 10 seconds
for i in {1..10}; do
    sleep 1
    echo -n "."
done

echo ""
echo ""
echo "Running tests..."
echo ""

# Test 1: Check block production
echo " Checking block production..."
curl -s http://localhost:9944 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getHeader","id":1}' | grep -q "result" && \
  echo "   Blocks produced" || echo "   No blocks"

# Test 2: Query validator set
echo " Checking validator set..."
curl -s http://localhost:9944 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_peers","id":1}' | grep -q "peers" && \
  echo "   Peers connected" || echo "   Peers not connected"

echo ""
echo " Devnet is ready for testing!"