//! WASM host-function integration tests for C-01 / C-11 coverage.
//!
//! These tests exercise the **actual WASM runtime blob** via `WasmExecutor`.
//! They prove three things:
//!
//! 1. A real Groth16 proof submitted through `BlockBuilder_apply_extrinsic` succeeds
//!    and mutates shielded-assets state (commitment + nullifier stored).
//!
//! 2. The same proof is rejected when the host function `verify_bn254` returns `false`
//!    unconditionally (poisoned executor). State is not mutated.
//!
//! 3. Without `zc_groth_16::HostFunctions` registered the runtime blob cannot even
//!    be instantiated (proves the WASM binary imports the FFI symbol).
//!
//! All three tests use genuine WASM execution — not the native code path.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use codec::{Decode, Encode};
use frame_metadata_hash_extension::CheckMetadataHash;
use frame_system::{
    AuthorizeCall, CheckEra, CheckGenesis, CheckNonce, CheckNonZeroSender, CheckSpecVersion,
    CheckTxVersion, CheckWeight, WeightReclaim,
};
use pallet_transaction_payment::ChargeTransactionPayment;
use sc_executor::{sp_wasm_interface, WasmExecutionMethod, WasmExecutor, WasmtimeInstantiationStrategy};
use solochain_template_runtime::{
    BalancesConfig, Runtime, RuntimeCall, ShieldedAssetsConfig, SignedPayload, TxExtension,
    UncheckedExtrinsic, VERSION,
};
use sp_core::{Pair, H256};
use sp_io::TestExternalities;
use sp_keyring::Sr25519Keyring;
use sp_runtime::{
    generic::Era, BuildStorage, MultiAddress, MultiSignature,
};
use std::sync::OnceLock;
use frame_support::BoundedVec;
use sc_executor_common::runtime_blob::RuntimeBlob;
use transfer_circuit::TransferCircuit;
use zk_types::{Groth16Proof, ProofSubmission, ProofType, ShieldedTransferData, TransferPublicInputs};

// ─── Real-proof fixture (generated once per test run) ────────────────────────

struct ProofFixture {
    proof: Groth16Proof,
    inputs: TransferPublicInputs,
    vk_bytes: Vec<u8>,
}

static FIXTURE: OnceLock<ProofFixture> = OnceLock::new();

fn get_fixture() -> &'static ProofFixture {
    FIXTURE.get_or_init(|| {
        let mut rng = ark_std::rand::thread_rng();
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(TransferCircuit::default(), &mut rng)
                .expect("setup failed");
        let mut vk_bytes = Vec::new();
        vk.serialize_uncompressed(&mut vk_bytes).expect("VK serialization failed");

        let circuit = TransferCircuit::test_circuit();
        let merkle_root = fr_to_bytes(circuit.merkle_root);
        let nullifier = fr_to_bytes(*circuit.nullifiers.first().expect("nullifier"));
        let commitment = fr_to_bytes(*circuit.output_commitments.first().expect("commitment"));
        let asset_id = fr_to_bytes(circuit.asset_id);
        let fee = fr_to_bytes(circuit.fee_commitment);

        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("prove failed");
        let mut proof_a = [0u8; 64];
        let mut proof_b = [0u8; 128];
        let mut proof_c = [0u8; 64];
        proof.a.serialize_uncompressed(&mut proof_a[..]).unwrap();
        proof.b.serialize_uncompressed(&mut proof_b[..]).unwrap();
        proof.c.serialize_uncompressed(&mut proof_c[..]).unwrap();

        ProofFixture {
            proof: Groth16Proof { a: proof_a, b: proof_b, c: proof_c },
            inputs: TransferPublicInputs {
                merkle_root,
                nullifiers: vec![nullifier],
                output_commitments: vec![commitment],
                asset_id,
                fee_commitment: fee,
            },
            vk_bytes,
        }
    })
}

fn fr_to_bytes(fr: Fr) -> [u8; 32] {
    let mut b = [0u8; 32];
    fr.serialize_uncompressed(&mut b[..]).unwrap();
    b
}

// ─── Host-function type aliases ───────────────────────────────────────────────

type ZcHostFunctions = (sp_io::SubstrateHostFunctions, zc_groth16_io::zc_groth_16::HostFunctions);
type SubstrateOnly = sp_io::SubstrateHostFunctions;

// ─── Poisoned host function (always returns false / 0) ────────────────────────

/// Implements the same FFI symbol (`ext_zc_groth_16_verify_bn254_version_1`)
/// but unconditionally returns 0 (false). Used to prove the WASM runtime acts
/// on the host function's return value, not on its own internal verification.
struct PoisonedZcGroth16;

impl sp_wasm_interface::HostFunctions for PoisonedZcGroth16 {
    fn host_functions() -> Vec<&'static dyn sp_wasm_interface::Function> {
        // `register_static` handles the wasmtime path; this vec is for the
        // legacy / polkavm path which is not used in these tests.
        vec![]
    }

    fn register_static<T>(registry: &mut T) -> Result<(), T::Error>
    where
        T: sp_wasm_interface::HostFunctionRegistry,
    {
        // PassFatPointerAndRead<&[u8]> packs (ptr, len) into a single i64 on the
        // WASM side (confirmed by: "expected type (func (param i64) (result i32))").
        registry.register_static(
            "ext_zc_groth_16_verify_bn254_version_1",
            |_packed: i64| -> i32 { 0 }, // always false
        )
    }
}

type PoisonedZcHostFunctions = (sp_io::SubstrateHostFunctions, PoisonedZcGroth16);

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn wasm_blob() -> RuntimeBlob {
    let bytes = solochain_template_runtime::WASM_BINARY
        .expect("WASM binary missing — run `cargo build --release` first");
    RuntimeBlob::uncompress_if_needed(bytes).expect("invalid WASM blob")
}

fn make_executor<H: sp_wasm_interface::HostFunctions>() -> WasmExecutor<H> {
    WasmExecutor::builder()
        .with_execution_method(WasmExecutionMethod::Compiled {
            instantiation_strategy: WasmtimeInstantiationStrategy::RecreateInstance,
        })
        .build()
}

/// Build genesis externalities with Alice funded and the merkle root pre-set.
fn build_genesis(merkle_root: [u8; 32]) -> TestExternalities {
    let alice = Sr25519Keyring::Alice.to_account_id();
    let genesis = solochain_template_runtime::RuntimeGenesisConfig {
        balances: BalancesConfig {
            balances: vec![(alice, 1_000_000_000_000_000_000u128)],
            ..Default::default()
        },
        shielded_assets: ShieldedAssetsConfig {
            initial_merkle_root: Some(merkle_root),
            _phantom: Default::default(),
        },
        ..Default::default()
    };
    let storage = genesis.build_storage().expect("genesis failed");
    TestExternalities::from(storage)
}

/// Set the Groth16 verifying key directly in storage (bypasses root-only extrinsic).
fn set_vk(ext: &mut TestExternalities, vk_bytes: &[u8]) {
    ext.execute_with(|| {
        let bounded: BoundedVec<
            u8,
            <Runtime as pallet_proof_verifier::Config>::MaxVerifyingKeySize,
        > = vk_bytes.to_vec().try_into().expect("VK too large");
        pallet_proof_verifier::VerifyingKeys::<Runtime>::insert(
            ProofType::Groth16Transfer,
            bounded,
        );
    });
}

/// Call `Core_initialize_block` in WASM to prime the runtime for block 1.
///
/// After this call `BlockHash(0)` is absent (or zero-default), which matches
/// the `H256::zero()` we embed in the signed payload.
fn initialize_block<H: sp_wasm_interface::HostFunctions>(
    executor: &WasmExecutor<H>,
    ext: &mut TestExternalities,
) {
    let header = solochain_template_runtime::Header {
        parent_hash: H256::zero(),
        number: 1u32,
        state_root: H256::zero(),
        extrinsics_root: H256::zero(),
        digest: Default::default(),
    };
    executor
        .uncached_call(wasm_blob(), &mut ext.ext(), false, "Core_initialize_block", &header.encode())
        .expect("Core_initialize_block failed");
}

/// Build a signed `UncheckedExtrinsic` containing a ShieldedTransfer.
///
/// Signs with Alice (nonce 0, immortal era, genesis hash = H256::zero()).
fn make_signed_extrinsic(submission: ProofSubmission) -> UncheckedExtrinsic {
    let alice_pair = Sr25519Keyring::Alice.pair();
    let alice_account = Sr25519Keyring::Alice.to_account_id();

    let call = RuntimeCall::ProofVerifier(pallet_proof_verifier::Call::submit_proof {
        submission,
    });

    let tx_ext: TxExtension = (
        AuthorizeCall::<Runtime>::new(),
        CheckNonZeroSender::<Runtime>::new(),
        CheckSpecVersion::<Runtime>::new(),
        CheckTxVersion::<Runtime>::new(),
        CheckGenesis::<Runtime>::new(),
        CheckEra::<Runtime>::from(Era::Immortal),
        CheckNonce::<Runtime>::from(0u32),
        CheckWeight::<Runtime>::new(),
        ChargeTransactionPayment::<Runtime>::from(0u128),
        CheckMetadataHash::<Runtime>::new(false),
        WeightReclaim::<Runtime>::new(),
    );

    // Build the signing payload with hard-coded implicit values.
    // BlockHash(0) defaults to H256::zero() when never written, matching
    // what CheckGenesis and CheckEra (immortal) will compute in WASM.
    let implicit = (
        (),                          // AuthorizeCall
        (),                          // CheckNonZeroSender
        VERSION.spec_version,        // CheckSpecVersion
        VERSION.transaction_version, // CheckTxVersion
        H256::zero(),                // CheckGenesis  — BlockHash(0) default
        H256::zero(),                // CheckEra      — block hash for Immortal
        (),                          // CheckNonce
        (),                          // CheckWeight
        (),                          // ChargeTransactionPayment
        None::<[u8; 32]>,            // CheckMetadataHash — Disabled
        (),                          // WeightReclaim
    );

    let signed_payload = SignedPayload::from_raw(call.clone(), tx_ext.clone(), implicit);
    let raw_sig = alice_pair.sign(&signed_payload.encode());

    UncheckedExtrinsic::new_signed(
        call,
        MultiAddress::Id(alice_account),
        MultiSignature::Sr25519(raw_sig),
        tx_ext,
    )
}

/// Decode `ApplyExtrinsicResult` from the raw bytes returned by `BlockBuilder_apply_extrinsic`.
///
/// Returns `Ok(Ok(()))` on success, `Ok(Err(dispatch_error))` on dispatch failure,
/// `Err(InvalidTransaction)` on validity failure.
fn decode_apply_result(raw: Vec<u8>) -> sp_runtime::ApplyExtrinsicResult {
    Decode::decode(&mut &raw[..]).expect("failed to decode ApplyExtrinsicResult")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// **Test 1 — real proof**: genuine WASM execution via `BlockBuilder_apply_extrinsic`
/// succeeds and updates shielded-assets state (nullifier + commitment stored).
#[test]
fn wasm_real_proof_applies_extrinsic() {
    let f = get_fixture();
    let mut ext = build_genesis(f.inputs.merkle_root);
    set_vk(&mut ext, &f.vk_bytes);

    let executor = make_executor::<ZcHostFunctions>();
    initialize_block(&executor, &mut ext);

    let submission = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
        proof: f.proof.clone(),
        inputs: f.inputs.clone(),
        memos: vec![],
    }));
    let xt = make_signed_extrinsic(submission);
    let raw = executor
        .uncached_call(
            wasm_blob(),
            &mut ext.ext(),
            false,
            "BlockBuilder_apply_extrinsic",
            &xt.encode(),
        )
        .expect("BlockBuilder_apply_extrinsic call failed");

    let result = decode_apply_result(raw);
    assert_eq!(result, Ok(Ok(())), "expected extrinsic to succeed: {:?}", result);

    // Verify shielded-assets state was mutated by the WASM dispatch.
    ext.execute_with(|| {
        assert_eq!(pallet_shielded_assets::NullifierCount::<Runtime>::get(), 1,
            "nullifier not stored");
        assert_eq!(pallet_shielded_assets::CommitmentCount::<Runtime>::get(), 1,
            "commitment not stored");
        assert!(
            pallet_shielded_assets::NullifierSet::<Runtime>::contains_key(f.inputs.nullifiers[0]),
            "specific nullifier not in set"
        );
        assert_eq!(
            pallet_shielded_assets::Commitments::<Runtime>::get(0u64),
            Some(f.inputs.output_commitments[0]),
            "commitment mismatch"
        );
    });
}

/// **Test 2 — poisoned host function**: the same mathematically-valid proof is
/// rejected when `verify_bn254` returns `false` unconditionally. State is not
/// mutated. This proves the WASM runtime dispatches through the host function
/// and acts on its return value.
#[test]
fn wasm_poisoned_host_fn_rejects_proof() {
    let f = get_fixture();
    let mut ext = build_genesis(f.inputs.merkle_root);
    set_vk(&mut ext, &f.vk_bytes);

    // Use the poisoned executor — same host-function name, always returns false.
    let executor = make_executor::<PoisonedZcHostFunctions>();
    initialize_block(&executor, &mut ext);

    let submission = ProofSubmission::ShieldedTransfer(Box::new(ShieldedTransferData {
        proof: f.proof.clone(),
        inputs: f.inputs.clone(),
        memos: vec![],
    }));
    let xt = make_signed_extrinsic(submission);
    let raw = executor
        .uncached_call(
            wasm_blob(),
            &mut ext.ext(),
            false,
            "BlockBuilder_apply_extrinsic",
            &xt.encode(),
        )
        .expect("BlockBuilder_apply_extrinsic call failed");

    let result = decode_apply_result(raw);
    // Dispatch must fail — the host function returned false.
    match result {
        Ok(Err(_)) => { /* expected: dispatched but failed */ }
        other => panic!("expected Ok(Err(_)) from poisoned verifier, got {:?}", other),
    }

    // Shielded-assets state must be unchanged.
    ext.execute_with(|| {
        assert_eq!(pallet_shielded_assets::NullifierCount::<Runtime>::get(), 0,
            "nullifier must not be stored when proof fails");
        assert_eq!(pallet_shielded_assets::CommitmentCount::<Runtime>::get(), 0,
            "commitment must not be stored when proof fails");
    });
}

/// **Test 3 — missing host function**: the WASM blob cannot be instantiated at
/// all when `zc_groth_16::HostFunctions` is absent (strict mode). Confirms that
/// the binary genuinely imports `ext_zc_groth_16_verify_bn254_version_1`.
#[test]
fn wasm_fails_to_instantiate_without_zc_host_fn() {
    let mut ext = TestExternalities::default();

    let executor = make_executor::<SubstrateOnly>();
    let result = executor.uncached_call(
        wasm_blob(),
        &mut ext.ext(),
        false, // allow_missing_host_functions = false → strict
        "Core_version",
        &[],
    );

    assert!(
        result.is_err(),
        "expected instantiation failure without ZcGroth16 host function, got Ok"
    );
    let msg = format!("{:?}", result.unwrap_err());
    assert!(
        msg.contains("ext_zc_groth_16_verify_bn254_version_1")
            || msg.contains("missing")
            || msg.contains("import"),
        "error message should mention the missing import: {}",
        msg
    );
}
