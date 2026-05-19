use sc_service::ChainType;
use solochain_template_runtime::WASM_BINARY;

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

pub fn development_chain_spec() -> Result<ChainSpec, String> {
	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
		None,
	)
	.with_name("Development")
	.with_id("dev")
	.with_chain_type(ChainType::Development)
	.with_genesis_config_preset_name(sp_genesis_builder::DEV_RUNTIME_PRESET)
	.build())
}

pub fn local_chain_spec() -> Result<ChainSpec, String> {
	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
		None,
	)
	.with_name("Local Testnet")
	.with_id("local_testnet")
	.with_chain_type(ChainType::Local)
	.with_genesis_config_preset_name(sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET)
	.build())
}

//! 3-node Devnet Chain Specification
//! 
//! Nodes: Alice (validator), Bob (validator), Charlie (validator)
//! Consensus: BLS 2-of-3 threshold
//! Privacy: Dandelion++ stem phase (4 hops)

use sp_core::{sr25519, Pair};
use std::str::FromStr;

pub fn devnet_config() -> Result<ChainSpec, String> {
    ChainSpec::from_genesis(
        "ZeroChain Devnet",
        "zerochain-devnet",
        ChainType::Development,
        devnet_genesis_config,
        // Bootnodes
        vec![],
        // Telemetry endpoints
        None,
        // Protocol ID
        None,
        // Fork ID
        None,
        // Properties
        None,
        // Extensions
        Default::default(),
    )
}

fn devnet_genesis_config() -> GenesisConfig {
    use node::runtime::{
        AccountId, Balance, BlsConsensusConfig, DandelionConfig, RuntimeGenesisConfig, SystemConfig,
        WASM_BINARY,
    };

    let alice = get_account_id_from_seed::<sr25519::Public>("Alice");
    let bob = get_account_id_from_seed::<sr25519::Public>("Bob");
    let charlie = get_account_id_from_seed::<sr25519::Public>("Charlie");

    GenesisConfig {
        system: SystemConfig {
            code: WASM_BINARY.unwrap().to_vec(),
            ..Default::default()
        },

        // 2-of-3 BLS consensus
        bls_consensus: BlsConsensusConfig {
            validators: vec![alice, bob, charlie],
            threshold: 2,
        },

        // Dandelion++ config
        dandelion: DandelionConfig {
            stem_hops: 4,
            stem_probability: 0.6,
        },

        // Balance for validators
        balances: BalancesConfig {
            balances: vec![
                (alice, 10_000_000_000_000_000u128),
                (bob, 10_000_000_000_000_000u128),
                (charlie, 10_000_000_000_000_000u128),
            ],
        },

        ..Default::default()
    }
}

fn get_account_id_from_seed<PublicKey: From<sr25519::Public> + std::fmt::Debug>(
    seed: &str,
) -> AccountId {
    PublicKey::from(sr25519::Pair::from_string(
        &format!("//{}", seed),
        None,
    )
    .expect("static values are valid; qed"))
    .into()
}