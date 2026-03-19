# Zero Chain

A blockchain where the people running the network are as invisible as the transactions on it.

Every privacy blockchain out there hides what users send to each other. Fine. But the validators processing those transactions? Completely visible. You can find Monero miners on the public internet. You can map the Zcash network. If someone wants to attack the chain, they don't need to break the math. They just need to find the validators.

Zero Chain is our answer to that. Validators prove they belong to the network using zero-knowledge proofs. No identities, no IP addresses linked to public keys, no list of targets for anyone to go after.

## What it does

Three things, none of which exist together in any other chain right now:

**Private transactions.** A user sends value and nobody can see who sent it, who received it, or how much moved. We use Groth16 proofs over BN254 for this, same family of cryptography as Zcash shielded transactions.

**Anonymous validators.** The machines producing blocks can't be identified. Each validator proves it belongs to the active set using a Halo2 membership proof. The proof says "I'm one of you" without saying which one.

**Verified state lineage.** This is the ZK-ORIGIN piece. Every state change on the chain carries a recursive proof (Nova folding) that traces it back to a legitimate origin. Bridges between blockchains have lost over $2 billion because chains could verify a message was formatted correctly but couldn't verify it actually came from where it said it did. ZK-ORIGIN fixes that problem.

## Where things stand

This repo has the working solochain base. Substrate chain, compiles, produces blocks, consensus works. We're building the ZK pallets and circuits on top of this right now.

Prototype goal: a private transaction proved off-chain and verified on-chain, running on a three-node devnet.

## Tech stack

Rust. Substrate (from the Polkadot SDK) as the blockchain framework. arkworks for Groth16 transaction proofs. Halo2 for validator membership proofs. Nova for the recursive state lineage system. Poseidon for hashing inside circuits (way cheaper than SHA-256 in ZK). AURA and GRANDPA for consensus during the prototype phase.

## Setup

### Prerequisites (all platforms)

- Rust 1.93 or newer (stable)
- The `wasm32-unknown-unknown` Rust target
- Git
- A C/C++ compiler
- 16 GB RAM minimum. 32 GB recommended. Substrate compilation alone eats 8-12 GB.
- 50 GB free disk space. Rust build artifacts for Substrate fill up 30-50 GB over time.

### macOS

Get Homebrew if you don't already have it:

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Install the dependencies:

```
brew install llvm cmake protobuf
```

This next part is important. RocksDB (the database Substrate uses) needs to find the LLVM libraries. If you skip this, the build will fail with a `libclang.dylib not found` error and it will be confusing.

For Apple Silicon Macs (M1, M2, M3, M4):

```
echo 'export LIBCLANG_PATH="/opt/homebrew/opt/llvm/lib"' >> ~/.zshrc
source ~/.zshrc
```

For Intel Macs:

```
echo 'export LIBCLANG_PATH="/usr/local/opt/llvm/lib"' >> ~/.zshrc
source ~/.zshrc
```

Install Rust if you don't have it:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add wasm32-unknown-unknown
```

### Linux (Ubuntu / Debian)

```
sudo apt update
sudo apt install -y build-essential git clang curl libssl-dev llvm libudev-dev protobuf-compiler pkg-config cmake
```

Then Rust:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add wasm32-unknown-unknown
```

### Linux (Fedora / RHEL)

```
sudo dnf install -y git clang curl openssl-devel llvm protobuf-compiler cmake pkg-config
sudo dnf group install -y "C Development Tools and Libraries"
```

Then Rust:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add wasm32-unknown-unknown
```

### Windows

Native Windows doesn't work. Use WSL2.

```
wsl --install
```

Restart your machine, open the Ubuntu terminal that shows up, and follow the Ubuntu instructions above. Everything runs inside WSL from there.

If you use VS Code, grab the "Remote - WSL" extension so you can edit files inside the WSL filesystem from your normal editor.

### Clone and build

```
git clone https://github.com/Maheshsiddu29/ZeroChain.git
cd ZeroChain
cargo build --release
```

First build takes 15 to 30 minutes. That is normal. Substrate pulls in around 1200 crates. After the first build, only changed code recompiles so it gets much faster.

### Run it

```
./target/release/solochain-template-node --dev
```

If it's working you'll see blocks coming in every few seconds:

```
🏆 Imported #1 (0x0d7f...0530 -> 0xd7f3...5a61)
🏆 Imported #2 (0xd7f3...5a61 -> 0x8de3...cdcb)
🏆 Imported #3 (0x8de3...cdcb -> 0x186a...e864)
```

Ctrl+C to stop.

### Block explorer

While the chain is running, open this in a browser:

```
https://polkadot.js.org/apps/?rpc=ws://127.0.0.1:9944
```

Lets you look at blocks, submit transactions, read storage, and watch events.

## Project layout

```
zerochain/
  node/          -- the binary that runs the chain
  runtime/       -- on-chain logic compiled to WASM
  pallets/
    template/    -- starter pallet (getting replaced with our custom ones)
```

We're adding these next:

- `pallets/proof-verifier` -- verifies Groth16, Halo2, and Nova proofs on-chain
- `pallets/shielded-assets` -- private transfers using commitment trees and nullifiers
- `pallets/zk-validator` -- anonymous validator set with ZK membership proofs

## Common build problems

**`libclang.dylib not found` on macOS**

LLVM isn't installed or the path isn't set. Run:

```
brew install llvm
