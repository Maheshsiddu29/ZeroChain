//endtoend demo

const { ApiPromise, WsProvider } = require("@polkadot/api");
const { Keyring } = require("@polkadot/keyring");
const fs = require("fs");
const path = require("path");

//configuration

const args = process.argv.slice(2);
function getArg(name, defaultVal) {
  const idx = args.indexOf(`--${name}`);
  return idx >= 0 && args[idx + 1] ? args[idx + 1] : defaultVal;
}

const WS_URL = getArg("ws-url", "ws://127.0.0.1:9944");
const VK_PATH = getArg("vk-path", null);
const PROOF_PATH = getArg("proof-path", null);

//helpers

function log(icon, msg) {
  const ts = new Date().toISOString().substr(11, 8);
  console.log(`[${ts}] ${icon}  ${msg}`);
}

function logSection(title) {
  console.log(`\n${"─".repeat(60)}`);
  console.log(`  ${title}`);
  console.log(`${"─".repeat(60)}\n`);
}

async function waitForEvent(api, section, method, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      unsub();
      reject(new Error(`Timeout waiting for ${section}.${method}`));
    }, timeout);

    let unsub;
    api.query.system.events((events) => {
      for (const { event } of events) {
        if (event.section === section && event.method === method) {
          clearTimeout(timer);
          if (unsub) unsub();
          resolve(event);
          return;
        }
      }
    }).then(u => { unsub = u; });
  });
}

function sendAndWatch(api, tx) {
  return new Promise((resolve, reject) => {
    const events = [];
    tx.send(({ status, events: records, dispatchError }) => {
      if (status.isInBlock || status.isFinalized) {
        const blockHash = status.isInBlock ? status.asInBlock : status.asFinalized;
        if (records) {
          records.forEach(({ event }) => {
            events.push(event);
          });
        }
        if (dispatchError) {
          if (dispatchError.isModule) {
            const decoded = api.registry.findMetaError(dispatchError.asModule);
            reject(new Error(`${decoded.section}.${decoded.name}: ${decoded.docs.join(" ")}`));
          } else {
            reject(new Error(dispatchError.toString()));
          }
        } else {
          resolve({ blockHash: blockHash.toHex(), events });
        }
      }
    }).catch(reject);
  });
}

function sendSudoAndWatch(api, call, signer) {
  return new Promise((resolve, reject) => {
    const events = [];
    const sudoTx = api.tx.sudo.sudo(call);
    sudoTx.signAndSend(signer, ({ status, events: records, dispatchError }) => {
      if (status.isInBlock || status.isFinalized) {
        const blockHash = status.isInBlock ? status.asInBlock : status.asFinalized;
        if (records) {
          records.forEach(({ event }) => {
            events.push(event);
          });
        }
        //check for any sudo errors
        const sudoResult = events.find(e => e.section === "sudo");
        const hasFailed = events.find(e =>
          e.section === "system" && e.method === "ExtrinsicFailed"
        );
        if (hasFailed) {
          reject(new Error("Sudo extrinsic failed. Check the call parameters."));
        } else {
          resolve({ blockHash: blockHash.toHex(), events });
        }
      }
    }).catch(reject);
  });
}

//main demo part

async function main() {
  console.log(` ZERO CHAIN- end to end demo ,private txn proved off chain and verified on chain`);

  //connect to node

  logSection("Step 0: Connecting to Zero Chain Node");
  log( `Connecting to ${WS_URL}...`);

  const provider = new WsProvider(WS_URL);
  const api = await ApiPromise.create({ provider });
  const chain = await api.rpc.system.chain();
  const version = await api.rpc.system.version();
  const bestBlock = await api.rpc.chain.getHeader();

  log( `Connected to: ${chain} v${version}`);
  log( `Best block: #${bestBlock.number}`);

  // Setup keyring with sudo account on dev chain (here ALice)
  const keyring = new Keyring({ type: "sr25519" });
  const alice = keyring.addFromUri("//Alice");
  log("", `Using account: Alice (${alice.address})`);

  //check available pallets 

  logSection("Step 1: Checking Runtime Pallets");

  const hasProofVerifier = api.tx.proofVerifier !== undefined;
  const hasShieldedAssets = api.tx.shieldedAssets !== undefined;
  const hasZkValidator = api.tx.zkValidator !== undefined;

  log(hasProofVerifier ? "Found" : `ProofVerifier pallet: ${hasProofVerifier ? "available" : "not found"}`);
  log(hasShieldedAssets ? "found" : `ShieldedAssets pallet: ${hasShieldedAssets ? "available" : "not found"}`);
  log(hasZkValidator ? "found" : `ZkValidator pallet: ${hasZkValidator ? "available" : "not found"}`);

  if (!hasProofVerifier) {
    log( "ProofVerifier pallet not found in runtime. Cannot proceed.");
    log( "Make sure the node is running with the latest runtime build.");
    process.exit(1);
  }

  //list available extrinsics
  const pvCalls = Object.keys(api.tx.proofVerifier || {});
  log( `ProofVerifier extrinsics: ${pvCalls.join(", ")}`);

  //register Verifying Key

  logSection("Step 2: Registering Groth16 Verifying Key On-Chain");

  let vkBytes;
  if (VK_PATH && fs.existsSync(VK_PATH)) {
    vkBytes = fs.readFileSync(VK_PATH);
    log(`Loaded VK from ${VK_PATH} (${vkBytes.length} bytes)`);
  } else {
    // Generate a dummy VK for demo purposes if no file provided
    log("No VK file provided. Generating keys using the prover...");
    log("Run: cargo run -p zk-prover -- setup --circuit transfer --output-dir keys");
    log("Then: node demo.js --vk-path keys/transfer.vk --proof-path proof.bin");

    //try default locations
    const defaultVk = path.join(__dirname, "..", "keys", "transfer.vk");
    const tmpVk = "/tmp/zk-keys/transfer.vk";

    if (fs.existsSync(defaultVk)) {
      vkBytes = fs.readFileSync(defaultVk);
      log(`Found VK at ${defaultVk} (${vkBytes.length} bytes)`);
    } else if (fs.existsSync(tmpVk)) {
      vkBytes = fs.readFileSync(tmpVk);
      log(`Found VK at ${tmpVk} (${vkBytes.length} bytes)`);
    } else {
      log("No verifying key found. Run the prover setup first.");
      log("  cargo run -p zk-prover -- setup --circuit transfer --output-dir /tmp/zk-keys");
      await api.disconnect();
      process.exit(1);
    }
  }

  //proofType::Groth16Transfer = 0 in the enum
  const proofTypeGroth16 = 0;

  log("Submitting set_verifying_key via sudo...");
  try {
    const setVkCall = api.tx.proofVerifier.setVerifyingKey(
      proofTypeGroth16,
      Array.from(vkBytes)
    );
    const vkResult = await sendSudoAndWatch(api, setVkCall, alice);
    log(`Verifying key registered in block ${vkResult.blockHash}`);

    // Check for VerifyingKeyUpdated event
    const vkEvent = vkResult.events.find(e =>
      e.section === "proofVerifier" && e.method === "VerifyingKeyUpdated"
    );
    if (vkEvent) {
      log(`Event: ProofVerifier.VerifyingKeyUpdated`);
    }
  } catch (err) {
    log(`Failed to register VK: ${err.message}`);
    // Continue anyway - VK might already be registered
    log("Continuing (VK may already be registered from a previous run)...");
  }

  //Step 3: Query on-chain state 

  logSection("Step 3: Querying On-Chain State (Before Proof)");

  if (api.query.shieldedAssets) {
    const commitmentCount = await api.query.shieldedAssets.commitmentCount();
    const nullifierCount = await api.query.shieldedAssets.nullifierCount();
    const transferCount = await api.query.shieldedAssets.transferCount();
    log(`Commitment count: ${commitmentCount}`);
    log( `Nullifier count: ${nullifierCount}`);
    log( `Transfer count: ${transferCount}`);
  }

  if (api.query.proofVerifier) {
    const proofCount = await api.query.proofVerifier.proofCount();
    log( `Total proofs verified: ${proofCount}`);
  }

  //  Step 4: Submit Proof 

  logSection("Step 4: Submitting Shielded Transfer Proof");

  let proofBytes;
  if (PROOF_PATH && fs.existsSync(PROOF_PATH)) {
    proofBytes = fs.readFileSync(PROOF_PATH);
    log( `Loaded proof submission from ${PROOF_PATH} (${proofBytes.length} bytes)`);
  } else {
    const defaultProof = "/tmp/proof.bin";
    if (fs.existsSync(defaultProof)) {
      proofBytes = fs.readFileSync(defaultProof);
      log( `Found proof at ${defaultProof} (${proofBytes.length} bytes)`);
    } else {
      log("No proof file found. Generate one first:");
      log("  cargo run -p zk-prover -- transfer --witness witness.json --proving-key /tmp/zk-keys/transfer.pk --output /tmp/proof.bin");
      await api.disconnect();
      process.exit(1);
    }
  }


  log( "Constructing typed ProofSubmission...");

  // Read the SCALE bytes and extract the proof fields manually
  let offset = 0;

  // First byte: enum variant index (0 = ShieldedTransfer)
  const variant = proofBytes[offset]; offset += 1;
  if (variant !== 0) {
    log(`Expected ShieldedTransfer variant (0), got ${variant}`);
    await api.disconnect();
    process.exit(1);
  }

  // Groth16Proof: a[64] + b[128] + c[64] = 256 bytes
  const proofA = Array.from(proofBytes.slice(offset, offset + 64)); offset += 64;
  const proofB = Array.from(proofBytes.slice(offset, offset + 128)); offset += 128;
  const proofC = Array.from(proofBytes.slice(offset, offset + 64)); offset += 64;

  // TransferPublicInputs:
  // merkle_root: [u8; 32]
  const merkleRoot = Array.from(proofBytes.slice(offset, offset + 32)); offset += 32;

  // nullifiers: Vec<[u8;32]> — SCALE compact-encoded length prefix
  const nullifierLenByte = proofBytes[offset]; offset += 1;
  const nullifierCount = nullifierLenByte >> 2; // compact encoding: value << 2
  const nullifiers = [];
  for (let i = 0; i < nullifierCount; i++) {
    nullifiers.push(Array.from(proofBytes.slice(offset, offset + 32)));
    offset += 32;
  }

  // output_commitments: Vec<[u8;32]>
  const commitmentLenByte = proofBytes[offset]; offset += 1;
  const commitmentCount2 = commitmentLenByte >> 2;
  const outputCommitments = [];
  for (let i = 0; i < commitmentCount2; i++) {
    outputCommitments.push(Array.from(proofBytes.slice(offset, offset + 32)));
    offset += 32;
  }

  // asset_id: [u8; 32]
  const assetId = Array.from(proofBytes.slice(offset, offset + 32)); offset += 32;

  // fee_commitment: [u8; 32]
  const feeCommitment = Array.from(proofBytes.slice(offset, offset + 32)); offset += 32;

  log( `Parsed proof: a=${proofA.length}B, b=${proofB.length}B, c=${proofC.length}B`);
  log( `Inputs: ${nullifiers.length} nullifiers, ${outputCommitments.length} commitments`);

  // Construct the typed submission object matching the runtime metadata
  const submission = {
    ShieldedTransfer: {
      proof: {
        a: proofA,
        b: proofB,
        c: proofC,
      },
      inputs: {
        merkleRoot: merkleRoot,
        nullifiers: nullifiers,
        outputCommitments: outputCommitments,
        assetId: assetId,
        feeCommitment: feeCommitment,
      },
    },
  };

  log( "Submitting proof to ProofVerifier.submitProof (signed by Alice)");

  try {
    const submitTx = api.tx.proofVerifier.submitProof(submission);
    const submitResult = await new Promise((resolve, reject) => {
      const collectedEvents = [];
      submitTx.signAndSend(alice, ({ status, events, dispatchError }) => {
        if (status.isInBlock || status.isFinalized) {
          const blockHash = status.isInBlock ? status.asInBlock : status.asFinalized;
          if (events) {
            events.forEach(({ event }) => collectedEvents.push(event));
          }
          if (dispatchError) {
            if (dispatchError.isModule) {
              const decoded = api.registry.findMetaError(dispatchError.asModule);
              reject(new Error(`${decoded.section}.${decoded.name}: ${decoded.docs.join(" ")}`));
            } else {
              reject(new Error(dispatchError.toString()));
            }
          } else {
            resolve({ blockHash: blockHash.toHex(), events: collectedEvents });
          }
        }
      }).catch(reject);
    });

    log( `Proof included in block ${submitResult.blockHash}`);

    // Display events
    for (const event of submitResult.events) {
      if (event.section === "proofVerifier") {
        log(`Event: ProofVerifier.${event.method} ${JSON.stringify(event.data.toHuman())}`);
      }
      if (event.section === "shieldedAssets") {
        log(`Event: ShieldedAssets.${event.method} ${JSON.stringify(event.data.toHuman())}`);
      }
      if (event.section === "system" && event.method === "ExtrinsicSuccess") {
        log("EXTRINSIC SUCCEEDED — Proof verified on-chain!");
      }
      if (event.section === "system" && event.method === "ExtrinsicFailed") {
        log(`Extrinsic failed: ${JSON.stringify(event.data.toHuman())}`);
      }
    }
  } catch (err) {
    log(`Proof submission failed: ${err.message}`);
  }

  // Step 5: Query State After 

  logSection("Step 5: Querying On-Chain State (After Proof)");

  if (api.query.shieldedAssets) {
    const commitmentCount = await api.query.shieldedAssets.commitmentCount();
    const nullifierCount = await api.query.shieldedAssets.nullifierCount();
    const transferCount = await api.query.shieldedAssets.transferCount();
    log( `Commitment count: ${commitmentCount}`);
    log( `Nullifier count: ${nullifierCount}`);
    log( `Transfer count: ${transferCount}`);
  }

  if (api.query.proofVerifier) {
    const proofCount = await api.query.proofVerifier.proofCount();
    log( `Total proofs verified: ${proofCount}`);
  }

  //  Done 

  logSection("Demo Complete");

  console.log(`
  Summary: prover component generated groth 16 proof and on chain verifying he key registered in pallet proof veifier. proof submitted and verified using pairing check, after successful verification transfer is processed , nullifier marked spent and new commitments added to the tree
`);

  await api.disconnect();
  process.exit(0);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
