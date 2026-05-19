#![cfg_attr(not(feature = "std"), no_std)]
#![recursion_limit = "256"]

use frame_support::{
    construct_runtime, parameter_types,
    traits::{ConstU128, ConstU32, ConstU64, ConstU8},
    weights::{
        constants::{BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
        IdentityFee, Weight,
    },
};
use sp_api::impl_runtime_apis;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{crypto::KeyTypeId, OpaqueMetadata, H256};
use sp_runtime::{
    create_runtime_str, generic, impl_opaque_keys,
    traits::{
        BlakeTwo256, Block as BlockT, IdentifyAccount, NumberFor, One, Verify,
    },
    transaction_validity::{TransactionSource, TransactionValidity},
    ApplyExtrinsicResult, MultiSignature,
};
use sp_std::prelude::*;
use sp_version::RuntimeVersion;

pub use frame_support::{
    dispatch::DispatchClass,
    pallet_prelude::Get,
};
pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;
pub use sp_runtime::{MultiAddress, Perbill, Permill};

#[cfg(feature = "std")]
use sp_version::NativeVersion;

// ZK Pallets
use pallet_proof_verifier;
use pallet_shielded_assets;
use pallet_zk_validator;

pub mod apis;

/// Opaque types
pub mod opaque {
    use super::*;
    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    pub type BlockId = generic::BlockId<Block>;

    impl_opaque_keys! {
        pub struct SessionKeys {
            pub aura: Aura,
            pub grandpa: Grandpa,
        }
    }
}

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: create_runtime_str!("zerochain"),
    impl_name: create_runtime_str!("zerochain-node"),
    authoring_version: 1,
    spec_version: 1,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 1,
    state_version: 1,
};

pub const MILLISECS_PER_BLOCK: u64 = 6000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;

// Time constants
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

// Type definitions
pub type BlockNumber = u32;
pub type Signature = MultiSignature;
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type Balance = u128;
pub type Nonce = u32;
pub type Hash = H256;
pub type Moment = u64;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;

pub const EXISTENTIAL_DEPOSIT: u128 = 500;

#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
    pub const BlockHashCount: BlockNumber = 2400;
    pub const Version: RuntimeVersion = VERSION;
    pub const SS58Prefix: u8 = 42;
    pub BlockWeights: frame_system::limits::BlockWeights =
        frame_system::limits::BlockWeights::with_sensible_defaults(
            Weight::from_parts(2u64 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX),
            NORMAL_DISPATCH_RATIO,
        );
    pub BlockLength: frame_system::limits::BlockLength = frame_system::limits::BlockLength
        ::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
}

// ===== CORE PALLET CONFIGS =====

impl frame_system::Config for Runtime {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = BlockWeights;
    type BlockLength = BlockLength;
    type DbWeight = RocksDbWeight;
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = Nonce;
    type Hash = Hash;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = sp_runtime::traits::AccountIdLookup<AccountId, ()>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = BlockHashCount;
    type Version = Version;
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = SS58Prefix;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

parameter_types! {
    pub const MinimumPeriod: Moment = SLOT_DURATION / 2;
}

impl pallet_timestamp::Config for Runtime {
    type Moment = Moment;
    type OnTimestampSet = Aura;
    type MinimumPeriod = MinimumPeriod;
    type WeightInfo = ();
}

impl pallet_aura::Config for Runtime {
    type AuthorityId = AuraId;
    type DisabledValidators = ();
    type MaxAuthorities = ConstU32<32>;
    type AllowMultipleBlocksPerSlot = ConstBool<false>;
    type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Runtime>;
}

impl pallet_grandpa::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type MaxAuthorities = ConstU32<32>;
    type MaxNominators = ConstU32<0>;
    type MaxSetIdSessionEntries = ConstU64<0>;
    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();
}

parameter_types! {
    pub const MaxLocks: u32 = 50;
    pub const MaxReserves: u32 = 50;
}

impl pallet_balances::Config for Runtime {
    type MaxLocks = MaxLocks;
    type MaxReserves = MaxReserves;
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ConstU128<EXISTENTIAL_DEPOSIT>;
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
    type FreezeIdentifier = ();
    type MaxFreezes = ConstU32<0>;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
}

parameter_types! {
    pub const OperationalFeeMultiplier: u8 = 5;
}

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction = pallet_transaction_payment::FungibleAdapter<Balances, ()>;
    type WeightToFee = IdentityFee<Balance>;
    type LengthToFee = IdentityFee<Balance>;
    type FeeMultiplierUpdate = ();
    type OperationalFeeMultiplier = OperationalFeeMultiplier;
}

impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

// ===== ZK PALLET CONFIGS =====

parameter_types! {
    pub const MaxValidators: u32 = 1000;
}

impl pallet_zk_validator::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MaxValidators = MaxValidators;
}

parameter_types! {
    pub const MaxCommitments: u32 = 1_000_000;
    pub const MaxNullifiers: u32 = 1_000_000;
    type MerkleRootHistory: u32 = 100;
}

impl pallet_shielded_assets::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MaxCommitments = MaxCommitments;
    type MaxNullifiers = MaxNullifiers;
    type MerkleRootHistory = MerkleRootHistory;
}

parameter_types! {
    pub const MaxProofSize: u32 = 1024 * 1024; // 1MB
}

impl pallet_proof_verifier::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type TransferHandler = ShieldedAssets;
    type MaxProofSize = MaxProofSize;
}

// ===== CONSTRUCT RUNTIME =====

construct_runtime!(
    pub enum Runtime {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Aura: pallet_aura,
        Grandpa: pallet_grandpa,
        Balances: pallet_balances,
        TransactionPayment: pallet_transaction_payment,
        Sudo: pallet_sudo,

        // ZK Pallets
        ZkValidator: pallet_zk_validator,
        ShieldedAssets: pallet_shielded_assets,
        ProofVerifier: pallet_proof_verifier,
    }
);

pub type Address = MultiAddress<AccountId, ()>;
pub type SignedExtra = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);

pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
>;

// ===== RUNTIME APIS =====

impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> RuntimeVersion {
            VERSION
        }

        fn execute_block(block: Block) {
            Executive::execute_block(block)
        }

        fn initialize_block(header: &<Block as BlockT>::Header) -> sp_runtime::ExtrinsicInclusionMode {
            Executive::initialize_block(header)
        }
    }

    impl sp_api::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata {
            OpaqueMetadata::new(Runtime::metadata().into())
        }

        fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> {
            Runtime::metadata_at_version(version)
        }

        fn metadata_versions() -> sp_std::vec::Vec<u32> {
            Runtime::metadata_versions()
        }
    }

    impl sp_block_builder::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: <Block as BlockT>::Extrinsic) -> ApplyExtrinsicResult {
            Executive::apply_extrinsic(extrinsic)
        }

        fn finalize_block() -> <Block as BlockT>::Header {
            Executive::finalize_block()
        }

        fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as BlockT>::Extrinsic> {
            data.create_extrinsics()
        }

        fn check_inherents(
            block: Block,
            data: sp_inherents::InherentData,
        ) -> sp_inherents::CheckInherentsResult {
            data.check_extrinsics(&block)
        }
    }

    impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: TransactionSource,
            tx: <Block as BlockT>::Extrinsic,
            block_hash: <Block as BlockT>::Hash,
        ) -> TransactionValidity {
            Executive::validate_transaction(source, tx, block_hash)
        }
    }

    impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
        fn offchain_worker(header: &<Block as BlockT>::Header) {
            Executive::offchain_worker(header)
        }
    }

    impl sp_consensus_aura::AuraApi<Block, AuraId> for Runtime {
        fn slot_duration() -> sp_consensus_aura::SlotDuration {
            sp_consensus_aura::SlotDuration::from_millis(SLOT_DURATION)
        }

        fn authorities() -> Vec<AuraId> {
            Aura::authorities().into_inner()
        }
    }

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(owner: Vec<u8>, seed: Option<Vec<u8>>) -> Vec<u8> {
            opaque::SessionKeys::generate(seed)
        }

        fn decode_session_keys(
            encoded: Vec<u8>,
        ) -> Option<Vec<(Vec<u8>, KeyTypeId)>> {
            opaque::SessionKeys::decode_into_raw_public_keys(&encoded)
        }
    }

    impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
        fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
            Grandpa::grandpa_authorities()
        }

        fn current_set_id() -> sp_consensus_grandpa::SetId {
            Grandpa::current_set_id()
        }

        fn submit_report_equivocation_unsigned_extrinsic(
            _equivocation_proof: sp_consensus_grandpa::EquivocationProof<
                <Block as BlockT>::Hash,
                NumberFor<Block>,
            >,
            _key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            None
        }

        fn generate_key_ownership_proof(
            _set_id: sp_consensus_grandpa::SetId,
            _authority_id: GrandpaId,
        ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
            None
        }
    }

    impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, Nonce> for Runtime {
        fn account_nonce(account: AccountId) -> Nonce {
            System::account_nonce(account)
        }
    }

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentApi<Block, Balance> for Runtime {
        fn query_info(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment_rpc_runtime_api::RuntimeDispatchInfo<Balance> {
            TransactionPayment::query_info(uxt, len)
        }

        fn query_fee_details(
            uxt: <Block as BlockT>::Extrinsic,
            len: u32,
        ) -> pallet_transaction_payment::FeeDetails<Balance> {
            TransactionPayment::query_fee_details(uxt, len)
        }

        fn query_weight_to_fee(weight: Weight) -> Balance {
            TransactionPayment::weight_to_fee(weight)
        }

        fn query_length_to_fee(length: u32) -> Balance {
            TransactionPayment::length_to_fee(length)
        }
    }

    impl pallet_transaction_payment_rpc_runtime_api::TransactionPaymentCallApi<Block, Balance, RuntimeCall>
        for Runtime
    {
        fn query_call_info(
            call: RuntimeCall,
            len: u32,
        ) -> pallet_transaction_payment::RuntimeDispatchInfo<Balance> {
            TransactionPayment::query_call_info(call, len)
        }

        fn query_call_fee_details(
            call: RuntimeCall,
            len: u32,
        ) -> pallet_transaction_payment::FeeDetails<Balance> {
            TransactionPayment::query_call_fee_details(call, len)
        }

        fn query_weight_to_fee(weight: Weight) -> Balance {
            TransactionPayment::weight_to_fee(weight)
        }

        fn query_length_to_fee(length: u32) -> Balance {
            TransactionPayment::length_to_fee(length)
        }
    }
}