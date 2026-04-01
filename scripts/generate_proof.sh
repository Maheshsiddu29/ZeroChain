#!/bin/bash
set -e

# Configuration
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PROOF_DIR="proof_archive/${TIMESTAMP}"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "     Zero Chain ZK Proof Generator with Metadata           "
echo -e "${NC}\n"

# Create directory structure
echo -e "${CYAN}Creating proof archive directory...${NC}"
mkdir -p ${PROOF_DIR}
echo -e "${GREEN} Created: ${PROOF_DIR}${NC}\n"

# Check if keys exist
if [ ! -f "keys/transfer.pk" ] || [ ! -f "keys/transfer.vk" ]; then
    echo -e "${YELLOW}Keys not found. Running setup...${NC}"
    cargo run --release -p zk-prover -- setup --circuit transfer --output-dir keys
    echo ""
fi

# Get key sizes for metadata
PK_SIZE=$(stat -f%z keys/transfer.pk 2>/dev/null || stat -c%s keys/transfer.pk 2>/dev/null)
VK_SIZE=$(stat -f%z keys/transfer.vk 2>/dev/null || stat -c%s keys/transfer.vk 2>/dev/null)

# Copy keys to archive
cp keys/transfer.pk ${PROOF_DIR}/transfer.pk
cp keys/transfer.vk ${PROOF_DIR}/transfer.vk

# Generate witness
echo -e "${CYAN}Step 1/4: Creating witness file...${NC}"
cat > ${PROOF_DIR}/witness.json << 'EOF'
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

WITNESS_SIZE=$(stat -f%z ${PROOF_DIR}/witness.json 2>/dev/null || stat -c%s ${PROOF_DIR}/witness.json 2>/dev/null)
echo -e "${GREEN} Witness created (${WITNESS_SIZE} bytes)${NC}\n"

# Generate proof with timing
echo -e "${CYAN}Step 2/4: Generating zero-knowledge proof...${NC}"
START_TIME=$(date +%s.%N)

cargo run --release -p zk-prover -- transfer \
  --witness ${PROOF_DIR}/witness.json \
  --proving-key ${PROOF_DIR}/transfer.pk \
  --output ${PROOF_DIR}/proof.bin 2>&1 | tee ${PROOF_DIR}/proof_generation.log

END_TIME=$(date +%s.%N)
PROOF_TIME=$(echo "$END_TIME - $START_TIME" | bc)

PROOF_SIZE=$(stat -f%z ${PROOF_DIR}/proof.bin 2>/dev/null || stat -c%s ${PROOF_DIR}/proof.bin 2>/dev/null)
echo -e "${GREEN} Proof generated (${PROOF_SIZE} bytes in ${PROOF_TIME}s)${NC}\n"

# Verify proof with timing
echo -e "${CYAN}Step 3/4: Verifying proof...${NC}"
START_TIME=$(date +%s.%N)

VERIFY_OUTPUT=$(cargo run --release -p zk-prover -- verify \
  --proof ${PROOF_DIR}/proof.bin \
  --vk ${PROOF_DIR}/transfer.vk 2>&1 | tee ${PROOF_DIR}/verification.log)

END_TIME=$(date +%s.%N)
VERIFY_TIME=$(echo "$END_TIME - $START_TIME" | bc)

if echo "$VERIFY_OUTPUT" | grep -q "Proof is VALID"; then
    VERIFICATION_STATUS="VALID"
    echo -e "${GREEN} Proof VERIFIED (${VERIFY_TIME}s)${NC}\n"
else
    VERIFICATION_STATUS="INVALID"
    echo -e "${RED} Proof INVALID${NC}\n"
fi

# Get system info
SYSTEM_INFO=$(uname -a)
CPU_INFO=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || cat /proc/cpuinfo | grep "model name" | head -1 | cut -d: -f2 | xargs 2>/dev/null || echo "Unknown")

# Create detailed metadata
echo -e "${CYAN}Step 4/4: Generating metadata and reports...${NC}"

cat > ${PROOF_DIR}/metadata.json << EOF
{
  "proof_id": "${TIMESTAMP}",
  "generation_info": {
    "timestamp": "${TIMESTAMP}",
    "datetime_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "datetime_local": "$(date)",
    "circuit_type": "transfer",
    "circuit_structure": {
      "inputs": 1,
      "outputs": 1,
      "merkle_depth": 32
    },
    "hash_function": "simplified_addition_dev_mode"
  },
  "file_sizes_bytes": {
    "witness": ${WITNESS_SIZE},
    "proof": ${PROOF_SIZE},
    "proving_key": ${PK_SIZE},
    "verifying_key": ${VK_SIZE},
    "total_archive": $((WITNESS_SIZE + PROOF_SIZE + PK_SIZE + VK_SIZE))
  },
  "file_sizes_human": {
    "witness": "$(numfmt --to=iec ${WITNESS_SIZE} 2>/dev/null || echo ${WITNESS_SIZE})",
    "proof": "$(numfmt --to=iec ${PROOF_SIZE} 2>/dev/null || echo ${PROOF_SIZE})",
    "proving_key": "$(numfmt --to=iec ${PK_SIZE} 2>/dev/null || echo ${PK_SIZE})",
    "verifying_key": "$(numfmt --to=iec ${VK_SIZE} 2>/dev/null || echo ${VK_SIZE})"
  },
  "performance_metrics": {
    "proof_generation_seconds": ${PROOF_TIME},
    "verification_seconds": ${VERIFY_TIME},
    "total_time_seconds": $(echo "$PROOF_TIME + $VERIFY_TIME" | bc)
  },
  "verification": {
    "status": "${VERIFICATION_STATUS}",
    "verified_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  },
  "transaction_details": {
    "value_smallest_unit": "100000000000000",
    "value_tokens": "100 ZERO",
    "asset_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "asset_name": "ZERO (native token)"
  },
  "system_info": {
    "os": "${SYSTEM_INFO}",
    "cpu": "${CPU_INFO}"
  },
  "files": [
    {"name": "witness.json", "size": ${WITNESS_SIZE}, "secret": true},
    {"name": "proof.bin", "size": ${PROOF_SIZE}, "secret": false},
    {"name": "transfer.pk", "size": ${PK_SIZE}, "secret": true},
    {"name": "transfer.vk", "size": ${VK_SIZE}, "secret": false},
    {"name": "metadata.json", "size": 0, "secret": false},
    {"name": "SUMMARY.md", "size": 0, "secret": false},
    {"name": "proof_generation.log", "size": 0, "secret": false},
    {"name": "verification.log", "size": 0, "secret": false}
  ]
}
EOF

# Get proof hex dump
PROOF_HEX=$(hexdump -C ${PROOF_DIR}/proof.bin | head -30)


# Create .gitignore
cat > ${PROOF_DIR}/.gitignore << 'EOF'
# Protect secrets
witness.json
transfer.pk

# Keep public artifacts
!proof.bin
!transfer.vk
!*.log
!*.md
!metadata.json
EOF

echo -e "${GREEN} Metadata files created${NC}\n"

# Display summary
echo -e "${CYAN}${BOLD}"
echo "                 PROOF GENERATION COMPLETE                 "
echo -e "${NC}\n"

echo -e "${YELLOW}${BOLD}Archive Location:${NC} ${PROOF_DIR}\n"

echo -e "${YELLOW}${BOLD}File Sizes:${NC}"
printf "  %-25s ${BOLD}%12s${NC} bytes\n" "Witness (SECRET):" "${WITNESS_SIZE}"
printf "  %-25s ${BOLD}%12s${NC} bytes ${GREEN}${BOLD}<== PROOF SIZE${NC}\n" "Proof:" "${PROOF_SIZE}"
printf "  %-25s ${BOLD}%12s${NC} bytes\n" "Proving Key (SECRET):" "${PK_SIZE}"
printf "  %-25s ${BOLD}%12s${NC} bytes\n" "Verifying Key:" "${VK_SIZE}"
echo ""

echo -e "${YELLOW}${BOLD}Performance:${NC}"
printf "  %-25s ${BOLD}%12s${NC} seconds\n" "Proof Generation:" "${PROOF_TIME}"
printf "  %-25s ${BOLD}%12s${NC} seconds\n" "Verification:" "${VERIFY_TIME}"
echo ""

echo -e "${YELLOW}${BOLD}Verification:${NC}"
if [ "$VERIFICATION_STATUS" = "VALID" ]; then
    echo -e "  Status: ${GREEN}${BOLD} VALID${NC}"
else
    echo -e "  Status: ${RED}${BOLD} INVALID${NC}"
fi
echo ""

echo -e "${YELLOW}${BOLD}Files Created:${NC}"
ls -lh ${PROOF_DIR}/ | tail -n +2 | awk '{printf "  %-35s %8s\n", $9, $5}'
echo ""

echo -e "${CYAN}${BOLD}Quick Commands:${NC}"
echo -e "  View metadata:  ${BOLD}cat ${PROOF_DIR}/metadata.json | jq '.'${NC}"
echo ""

echo -e "${GREEN}${BOLD} All proof artifacts saved to: ${PROOF_DIR}${NC}\n"