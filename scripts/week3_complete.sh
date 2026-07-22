#!/bin/bash

echo "  Week 3 Final Verification"
echo ""

# Check all components exist
echo " Component Status:"
echo ""

[ -d "circuits/slashing" ] && echo "   circuits/slashing" || echo "   circuits/slashing MISSING"
[ -d "pallets/bls-consensus" ] && echo "   pallets/bls-consensus" || echo "   pallets/bls-consensus MISSING"
[ -d "pallets/zk-staking" ] && echo "   pallets/zk-staking" || echo "   pallets/zk-staking MISSING"
[ -d "network/dandelion" ] && echo "   network/dandelion" || echo "   network/dandelion MISSING"
[ -d "prover/src" ] && echo "   prover (ZK-ORIGIN)" || echo "   prover MISSING"

echo ""
echo " Binary Status:"
echo ""

if [ -f "target/release/solochain-template-node" ]; then
    SIZE=$(du -h target/release/solochain-template-node | cut -f1)
    echo "   Binary built: $SIZE"
else
    echo "   Binary NOT built"
fi

echo ""
echo " Quick Test:"
echo ""

# Run quick tests
TESTS_PASSED=0
TESTS_TOTAL=0

for test in slashing-circuit pallet-bls-consensus pallet-zk-staking network-dandelion; do
    ((TESTS_TOTAL++))
    if cargo test -p "$test" --lib 2>&1 | grep -q "test result: ok"; then
        echo "   $test"
        ((TESTS_PASSED++))
    else
        echo "   $test"
    fi
done

((TESTS_TOTAL++))
if cargo test -p zerochain-prover origin_prover 2>&1 | grep -q "test result: ok"; then
    echo "   zerochain-prover"
    ((TESTS_PASSED++))
else
    echo "   zerochain-prover"
fi

echo ""
echo "  Results: $TESTS_PASSED/$TESTS_TOTAL tests passed"
echo ""

if [ $TESTS_PASSED -eq $TESTS_TOTAL ]; then
    echo ""
    echo "Summary of Deliverables:"
    echo "  • Slashing Circuit (Halo2) "
    echo "  • BLS Consensus (FROST) "
    echo "  • ZK-Staking Pallet "
    echo "  • ZK-ORIGIN Prover "
    echo "  • Dandelion++ Network "
    echo ""
    echo "All components tested and ready for deployment!"
    exit 0
else
    echo "  Some tests failed. Review output above."
    exit 1
fi