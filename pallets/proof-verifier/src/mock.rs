use crate as pallet_proof_verifier;
use frame_support::derive_impl;
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

#[frame_support::runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeFreezeReason,
        RuntimeHoldReason,
        RuntimeSlashReason,
        RuntimeLockId,
        RuntimeTask,
        RuntimeViewFunction
    )]
    pub struct Test;

    #[runtime::pallet_index(0)]
    pub type System = frame_system::Pallet<Test>;

    #[runtime::pallet_index(1)]
    pub type ProofVerifier = pallet_proof_verifier::Pallet<Test>;

    #[runtime::pallet_index(2)]
    pub type ShieldedAssets = pallet_shielded_assets::Pallet<Test>;
}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl pallet_proof_verifier::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxVerifyingKeySize = frame_support::traits::ConstU32<51200>;
    type MaxProofSize = frame_support::traits::ConstU32<10240>;
}

impl pallet_shielded_assets::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type MaxCommitments = frame_support::traits::ConstU32<1048576>;
    type MerkleRootHistory = frame_support::traits::ConstU32<32>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    let mut ext: sp_io::TestExternalities = t.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}