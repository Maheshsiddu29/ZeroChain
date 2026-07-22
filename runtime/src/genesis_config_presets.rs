// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{AccountId, BalancesConfig, RuntimeGenesisConfig, SudoConfig};
use alloc::{vec, vec::Vec};
use frame_support::build_struct_json_patch;
use serde_json::Value;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_genesis_builder::{self, PresetId};
use sp_keyring::Sr25519Keyring;

// Returns the genesis config presets populated with given parameters.
fn testnet_genesis(
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	endowed_accounts: Vec<AccountId>,
	root: AccountId,
) -> Value {
	build_struct_json_patch!(RuntimeGenesisConfig {
		balances: BalancesConfig {
			balances: endowed_accounts
				.iter()
				.cloned()
				.map(|k| (k, 1u128 << 60))
				.collect::<Vec<_>>(),
		},
		aura: pallet_aura::GenesisConfig {
			authorities: initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
		},
		grandpa: pallet_grandpa::GenesisConfig {
			authorities: initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>(),
		},
		sudo: SudoConfig { key: Some(root) },
	})
}

/// Return the development genesis config.
pub fn development_config_genesis() -> Value {
	testnet_genesis(
		vec![(
			sp_keyring::Sr25519Keyring::Alice.public().into(),
			sp_keyring::Ed25519Keyring::Alice.public().into(),
		)],
		vec![
			Sr25519Keyring::Alice.to_account_id(),
			Sr25519Keyring::Bob.to_account_id(),
			Sr25519Keyring::AliceStash.to_account_id(),
			Sr25519Keyring::BobStash.to_account_id(),
		],
		sp_keyring::Sr25519Keyring::Alice.to_account_id(),
	)
}

/// Production testnet genesis.
///
/// Uses Charlie + Dave as Aura/GRANDPA validators and Eve as sudo — not the
/// default dev keys (Alice/Bob).  The Groth16Transfer VK and the initial empty
/// Poseidon Merkle root are both seeded at genesis so no additional sudo
/// transactions are needed before the first real proof can be verified.
///
/// V-03: this is a single-party trusted setup — acceptable for testnet.
/// An MPC ceremony is required before mainnet.
pub fn production_testnet_genesis(
	groth16_transfer_vk: Vec<u8>,
	initial_merkle_root: [u8; 32],
) -> Value {
	// Single validator (Charlie) — sufficient for single-node testnet and
	// guarantees GRANDPA finalization with one running instance.
	// Add validators via governance before adding additional nodes.
	let initial_authorities: Vec<(AuraId, GrandpaId)> = vec![(
		sp_keyring::Sr25519Keyring::Charlie.public().into(),
		sp_keyring::Ed25519Keyring::Charlie.public().into(),
	)];

	// Sudo: Eve (not Alice/Bob)
	let root = sp_keyring::Sr25519Keyring::Eve.to_account_id();

	// Fund the sudo key and validators; keep endowment modest for testnet
	let endowed_accounts = vec![
		sp_keyring::Sr25519Keyring::Charlie.to_account_id(),
		sp_keyring::Sr25519Keyring::Dave.to_account_id(),
		sp_keyring::Sr25519Keyring::Eve.to_account_id(),
	];

	build_struct_json_patch!(RuntimeGenesisConfig {
		balances: BalancesConfig {
			balances: endowed_accounts
				.iter()
				.cloned()
				.map(|k| (k, 1u128 << 60))
				.collect::<Vec<_>>(),
		},
		aura: pallet_aura::GenesisConfig {
			authorities: initial_authorities.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
		},
		grandpa: pallet_grandpa::GenesisConfig {
			authorities: initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>(),
		},
		sudo: SudoConfig { key: Some(root) },
		proof_verifier: pallet_proof_verifier::GenesisConfig {
			initial_groth16_transfer_vk: Some(groth16_transfer_vk),
			_phantom: Default::default(),
		},
		shielded_assets: pallet_shielded_assets::GenesisConfig {
			initial_merkle_root: Some(initial_merkle_root),
			_phantom: Default::default(),
		},
	})
}

/// Return the local genesis config preset.
pub fn local_config_genesis() -> Value {
	testnet_genesis(
		vec![
			(
				sp_keyring::Sr25519Keyring::Alice.public().into(),
				sp_keyring::Ed25519Keyring::Alice.public().into(),
			),
			(
				sp_keyring::Sr25519Keyring::Bob.public().into(),
				sp_keyring::Ed25519Keyring::Bob.public().into(),
			),
		],
		Sr25519Keyring::iter()
			.filter(|v| v != &Sr25519Keyring::One && v != &Sr25519Keyring::Two)
			.map(|v| v.to_account_id())
			.collect::<Vec<_>>(),
		Sr25519Keyring::Alice.to_account_id(),
	)
}

/// Provides the JSON representation of predefined genesis config for given `id`.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
	let patch = match id.as_ref() {
		sp_genesis_builder::DEV_RUNTIME_PRESET => development_config_genesis(),
		sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET => local_config_genesis(),
		_ => return None,
	};
	Some(
		serde_json::to_string(&patch)
			.expect("serialization to json is expected to work. qed.")
			.into_bytes(),
	)
}

/// List of supported presets.
pub fn preset_names() -> Vec<PresetId> {
	vec![
		PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET),
		PresetId::from(sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET),
	]
}
